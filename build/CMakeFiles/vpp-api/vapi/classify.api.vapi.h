#ifndef __included_classify_api_json
#define __included_classify_api_json

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

extern vapi_msg_id_t vapi_msg_id_classify_add_del_table;
extern vapi_msg_id_t vapi_msg_id_classify_add_del_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_add_del_session;
extern vapi_msg_id_t vapi_msg_id_classify_add_del_session_reply;
extern vapi_msg_id_t vapi_msg_id_policer_classify_set_interface;
extern vapi_msg_id_t vapi_msg_id_policer_classify_set_interface_reply;
extern vapi_msg_id_t vapi_msg_id_policer_classify_dump;
extern vapi_msg_id_t vapi_msg_id_policer_classify_details;
extern vapi_msg_id_t vapi_msg_id_classify_table_ids;
extern vapi_msg_id_t vapi_msg_id_classify_table_ids_reply;
extern vapi_msg_id_t vapi_msg_id_classify_table_by_interface;
extern vapi_msg_id_t vapi_msg_id_classify_table_by_interface_reply;
extern vapi_msg_id_t vapi_msg_id_classify_table_info;
extern vapi_msg_id_t vapi_msg_id_classify_table_info_reply;
extern vapi_msg_id_t vapi_msg_id_classify_session_dump;
extern vapi_msg_id_t vapi_msg_id_classify_session_details;
extern vapi_msg_id_t vapi_msg_id_flow_classify_set_interface;
extern vapi_msg_id_t vapi_msg_id_flow_classify_set_interface_reply;
extern vapi_msg_id_t vapi_msg_id_flow_classify_dump;
extern vapi_msg_id_t vapi_msg_id_flow_classify_details;
extern vapi_msg_id_t vapi_msg_id_classify_set_interface_ip_table;
extern vapi_msg_id_t vapi_msg_id_classify_set_interface_ip_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_set_interface_l2_tables;
extern vapi_msg_id_t vapi_msg_id_classify_set_interface_l2_tables_reply;
extern vapi_msg_id_t vapi_msg_id_input_acl_set_interface;
extern vapi_msg_id_t vapi_msg_id_input_acl_set_interface_reply;
extern vapi_msg_id_t vapi_msg_id_punt_acl_add_del;
extern vapi_msg_id_t vapi_msg_id_punt_acl_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_punt_acl_get;
extern vapi_msg_id_t vapi_msg_id_punt_acl_get_reply;
extern vapi_msg_id_t vapi_msg_id_output_acl_set_interface;
extern vapi_msg_id_t vapi_msg_id_output_acl_set_interface_reply;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_lookup_table;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_lookup_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_set_table;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_set_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_get_tables;
extern vapi_msg_id_t vapi_msg_id_classify_pcap_get_tables_reply;
extern vapi_msg_id_t vapi_msg_id_classify_trace_lookup_table;
extern vapi_msg_id_t vapi_msg_id_classify_trace_lookup_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_trace_set_table;
extern vapi_msg_id_t vapi_msg_id_classify_trace_set_table_reply;
extern vapi_msg_id_t vapi_msg_id_classify_trace_get_tables;
extern vapi_msg_id_t vapi_msg_id_classify_trace_get_tables_reply;

#define DEFINE_VAPI_MSG_IDS_CLASSIFY_API_JSON\
  vapi_msg_id_t vapi_msg_id_classify_add_del_table;\
  vapi_msg_id_t vapi_msg_id_classify_add_del_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_add_del_session;\
  vapi_msg_id_t vapi_msg_id_classify_add_del_session_reply;\
  vapi_msg_id_t vapi_msg_id_policer_classify_set_interface;\
  vapi_msg_id_t vapi_msg_id_policer_classify_set_interface_reply;\
  vapi_msg_id_t vapi_msg_id_policer_classify_dump;\
  vapi_msg_id_t vapi_msg_id_policer_classify_details;\
  vapi_msg_id_t vapi_msg_id_classify_table_ids;\
  vapi_msg_id_t vapi_msg_id_classify_table_ids_reply;\
  vapi_msg_id_t vapi_msg_id_classify_table_by_interface;\
  vapi_msg_id_t vapi_msg_id_classify_table_by_interface_reply;\
  vapi_msg_id_t vapi_msg_id_classify_table_info;\
  vapi_msg_id_t vapi_msg_id_classify_table_info_reply;\
  vapi_msg_id_t vapi_msg_id_classify_session_dump;\
  vapi_msg_id_t vapi_msg_id_classify_session_details;\
  vapi_msg_id_t vapi_msg_id_flow_classify_set_interface;\
  vapi_msg_id_t vapi_msg_id_flow_classify_set_interface_reply;\
  vapi_msg_id_t vapi_msg_id_flow_classify_dump;\
  vapi_msg_id_t vapi_msg_id_flow_classify_details;\
  vapi_msg_id_t vapi_msg_id_classify_set_interface_ip_table;\
  vapi_msg_id_t vapi_msg_id_classify_set_interface_ip_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_set_interface_l2_tables;\
  vapi_msg_id_t vapi_msg_id_classify_set_interface_l2_tables_reply;\
  vapi_msg_id_t vapi_msg_id_input_acl_set_interface;\
  vapi_msg_id_t vapi_msg_id_input_acl_set_interface_reply;\
  vapi_msg_id_t vapi_msg_id_punt_acl_add_del;\
  vapi_msg_id_t vapi_msg_id_punt_acl_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_punt_acl_get;\
  vapi_msg_id_t vapi_msg_id_punt_acl_get_reply;\
  vapi_msg_id_t vapi_msg_id_output_acl_set_interface;\
  vapi_msg_id_t vapi_msg_id_output_acl_set_interface_reply;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_lookup_table;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_lookup_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_set_table;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_set_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_get_tables;\
  vapi_msg_id_t vapi_msg_id_classify_pcap_get_tables_reply;\
  vapi_msg_id_t vapi_msg_id_classify_trace_lookup_table;\
  vapi_msg_id_t vapi_msg_id_classify_trace_lookup_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_trace_set_table;\
  vapi_msg_id_t vapi_msg_id_classify_trace_set_table_reply;\
  vapi_msg_id_t vapi_msg_id_classify_trace_get_tables;\
  vapi_msg_id_t vapi_msg_id_classify_trace_get_tables_reply;


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

#ifndef defined_vapi_enum_classify_action
#define defined_vapi_enum_classify_action
typedef enum {
  CLASSIFY_API_ACTION_NONE = 0,
  CLASSIFY_API_ACTION_SET_IP4_FIB_INDEX = 1,
  CLASSIFY_API_ACTION_SET_IP6_FIB_INDEX = 2,
  CLASSIFY_API_ACTION_SET_METADATA = 3,
} __attribute__((packed)) vapi_enum_classify_action;

#endif

#ifndef defined_vapi_enum_policer_classify_table
#define defined_vapi_enum_policer_classify_table
typedef enum {
  POLICER_CLASSIFY_API_TABLE_IP4 = 0,
  POLICER_CLASSIFY_API_TABLE_IP6 = 1,
  POLICER_CLASSIFY_API_TABLE_L2 = 2,
} __attribute__((packed)) vapi_enum_policer_classify_table;

#endif

#ifndef defined_vapi_enum_flow_classify_table
#define defined_vapi_enum_flow_classify_table
typedef enum {
  FLOW_CLASSIFY_API_TABLE_IP4 = 0,
  FLOW_CLASSIFY_API_TABLE_IP6 = 1,
} __attribute__((packed)) vapi_enum_flow_classify_table;

#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_msg_classify_add_del_table_reply
#define defined_vapi_msg_classify_add_del_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 new_table_index;
  u32 skip_n_vectors;
  u32 match_n_vectors; 
} vapi_payload_classify_add_del_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_add_del_table_reply payload;
} vapi_msg_classify_add_del_table_reply;

static inline void vapi_msg_classify_add_del_table_reply_payload_hton(vapi_payload_classify_add_del_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->new_table_index = htobe32(payload->new_table_index);
  payload->skip_n_vectors = htobe32(payload->skip_n_vectors);
  payload->match_n_vectors = htobe32(payload->match_n_vectors);
}

static inline void vapi_msg_classify_add_del_table_reply_payload_ntoh(vapi_payload_classify_add_del_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->new_table_index = be32toh(payload->new_table_index);
  payload->skip_n_vectors = be32toh(payload->skip_n_vectors);
  payload->match_n_vectors = be32toh(payload->match_n_vectors);
}

static inline void vapi_msg_classify_add_del_table_reply_hton(vapi_msg_classify_add_del_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_add_del_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_add_del_table_reply_ntoh(vapi_msg_classify_add_del_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_add_del_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_add_del_table_reply_msg_size(vapi_msg_classify_add_del_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_add_del_table_reply_msg_size(vapi_msg_classify_add_del_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_add_del_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_add_del_table_reply));
      return -1;
    }
  if (vapi_calc_classify_add_del_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_add_del_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_add_del_table_reply()
{
  static const char name[] = "classify_add_del_table_reply";
  static const char name_with_crc[] = "classify_add_del_table_reply_05486349";
  static vapi_message_desc_t __vapi_metadata_classify_add_del_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_add_del_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_add_del_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_add_del_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_add_del_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_add_del_table_reply = vapi_register_msg(&__vapi_metadata_classify_add_del_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_add_del_table_reply", vapi_msg_id_classify_add_del_table_reply);
}

static inline void vapi_set_vapi_msg_classify_add_del_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_add_del_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_add_del_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_add_del_table
#define defined_vapi_msg_classify_add_del_table
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  bool del_chain;
  u32 table_index;
  u32 nbuckets;
  u32 memory_size;
  u32 skip_n_vectors;
  u32 match_n_vectors;
  u32 next_table_index;
  u32 miss_next_index;
  u8 current_data_flag;
  i16 current_data_offset;
  u32 mask_len;
  u8 mask[0]; 
} vapi_payload_classify_add_del_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_add_del_table payload;
} vapi_msg_classify_add_del_table;

static inline void vapi_msg_classify_add_del_table_payload_hton(vapi_payload_classify_add_del_table *payload)
{
  payload->table_index = htobe32(payload->table_index);
  payload->nbuckets = htobe32(payload->nbuckets);
  payload->memory_size = htobe32(payload->memory_size);
  payload->skip_n_vectors = htobe32(payload->skip_n_vectors);
  payload->match_n_vectors = htobe32(payload->match_n_vectors);
  payload->next_table_index = htobe32(payload->next_table_index);
  payload->miss_next_index = htobe32(payload->miss_next_index);
  payload->current_data_offset = htobe16(payload->current_data_offset);
  payload->mask_len = htobe32(payload->mask_len);
}

static inline void vapi_msg_classify_add_del_table_payload_ntoh(vapi_payload_classify_add_del_table *payload)
{
  payload->table_index = be32toh(payload->table_index);
  payload->nbuckets = be32toh(payload->nbuckets);
  payload->memory_size = be32toh(payload->memory_size);
  payload->skip_n_vectors = be32toh(payload->skip_n_vectors);
  payload->match_n_vectors = be32toh(payload->match_n_vectors);
  payload->next_table_index = be32toh(payload->next_table_index);
  payload->miss_next_index = be32toh(payload->miss_next_index);
  payload->current_data_offset = be16toh(payload->current_data_offset);
  payload->mask_len = be32toh(payload->mask_len);
}

static inline void vapi_msg_classify_add_del_table_hton(vapi_msg_classify_add_del_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_add_del_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_add_del_table_ntoh(vapi_msg_classify_add_del_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_add_del_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_add_del_table_msg_size(vapi_msg_classify_add_del_table *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.mask[0]) * msg->payload.mask_len;
}

static inline int vapi_verify_classify_add_del_table_msg_size(vapi_msg_classify_add_del_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_add_del_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_add_del_table));
      return -1;
    }
  if (vapi_calc_classify_add_del_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_add_del_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_add_del_table* vapi_alloc_classify_add_del_table(struct vapi_ctx_s *ctx, size_t _mask_array_size)
{
  vapi_msg_classify_add_del_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_add_del_table) + sizeof(msg->payload.mask[0]) * _mask_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_add_del_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_add_del_table);
  msg->payload.mask_len = _mask_array_size;

  return msg;
}

static inline vapi_error_e vapi_classify_add_del_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_add_del_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_add_del_table_reply *reply),
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
  vapi_msg_classify_add_del_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_add_del_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_add_del_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_add_del_table()
{
  static const char name[] = "classify_add_del_table";
  static const char name_with_crc[] = "classify_add_del_table_6849e39e";
  static vapi_message_desc_t __vapi_metadata_classify_add_del_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_add_del_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_add_del_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_add_del_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_add_del_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_add_del_table = vapi_register_msg(&__vapi_metadata_classify_add_del_table);
  VAPI_DBG("Assigned msg id %d to classify_add_del_table", vapi_msg_id_classify_add_del_table);
}
#endif

#ifndef defined_vapi_msg_classify_add_del_session_reply
#define defined_vapi_msg_classify_add_del_session_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_classify_add_del_session_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_add_del_session_reply payload;
} vapi_msg_classify_add_del_session_reply;

static inline void vapi_msg_classify_add_del_session_reply_payload_hton(vapi_payload_classify_add_del_session_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_classify_add_del_session_reply_payload_ntoh(vapi_payload_classify_add_del_session_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_classify_add_del_session_reply_hton(vapi_msg_classify_add_del_session_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_session_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_add_del_session_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_add_del_session_reply_ntoh(vapi_msg_classify_add_del_session_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_session_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_add_del_session_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_add_del_session_reply_msg_size(vapi_msg_classify_add_del_session_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_add_del_session_reply_msg_size(vapi_msg_classify_add_del_session_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_add_del_session_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_session_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_add_del_session_reply));
      return -1;
    }
  if (vapi_calc_classify_add_del_session_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_session_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_add_del_session_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_add_del_session_reply()
{
  static const char name[] = "classify_add_del_session_reply";
  static const char name_with_crc[] = "classify_add_del_session_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_classify_add_del_session_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_add_del_session_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_add_del_session_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_add_del_session_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_add_del_session_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_add_del_session_reply = vapi_register_msg(&__vapi_metadata_classify_add_del_session_reply);
  VAPI_DBG("Assigned msg id %d to classify_add_del_session_reply", vapi_msg_id_classify_add_del_session_reply);
}

static inline void vapi_set_vapi_msg_classify_add_del_session_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_add_del_session_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_add_del_session_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_add_del_session
#define defined_vapi_msg_classify_add_del_session
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 table_index;
  u32 hit_next_index;
  u32 opaque_index;
  i32 advance;
  vapi_enum_classify_action action;
  u32 metadata;
  u32 match_len;
  u8 match[0]; 
} vapi_payload_classify_add_del_session;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_add_del_session payload;
} vapi_msg_classify_add_del_session;

static inline void vapi_msg_classify_add_del_session_payload_hton(vapi_payload_classify_add_del_session *payload)
{
  payload->table_index = htobe32(payload->table_index);
  payload->hit_next_index = htobe32(payload->hit_next_index);
  payload->opaque_index = htobe32(payload->opaque_index);
  payload->advance = htobe32(payload->advance);
  payload->metadata = htobe32(payload->metadata);
  payload->match_len = htobe32(payload->match_len);
}

static inline void vapi_msg_classify_add_del_session_payload_ntoh(vapi_payload_classify_add_del_session *payload)
{
  payload->table_index = be32toh(payload->table_index);
  payload->hit_next_index = be32toh(payload->hit_next_index);
  payload->opaque_index = be32toh(payload->opaque_index);
  payload->advance = be32toh(payload->advance);
  payload->metadata = be32toh(payload->metadata);
  payload->match_len = be32toh(payload->match_len);
}

static inline void vapi_msg_classify_add_del_session_hton(vapi_msg_classify_add_del_session *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_session'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_add_del_session_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_add_del_session_ntoh(vapi_msg_classify_add_del_session *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_add_del_session'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_add_del_session_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_add_del_session_msg_size(vapi_msg_classify_add_del_session *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.match[0]) * msg->payload.match_len;
}

static inline int vapi_verify_classify_add_del_session_msg_size(vapi_msg_classify_add_del_session *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_add_del_session) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_session' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_add_del_session));
      return -1;
    }
  if (vapi_calc_classify_add_del_session_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_add_del_session' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_add_del_session_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_add_del_session* vapi_alloc_classify_add_del_session(struct vapi_ctx_s *ctx, size_t _match_array_size)
{
  vapi_msg_classify_add_del_session *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_add_del_session) + sizeof(msg->payload.match[0]) * _match_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_add_del_session*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_add_del_session);
  msg->payload.match_len = _match_array_size;

  return msg;
}

static inline vapi_error_e vapi_classify_add_del_session(struct vapi_ctx_s *ctx,
  vapi_msg_classify_add_del_session *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_add_del_session_reply *reply),
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
  vapi_msg_classify_add_del_session_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_add_del_session_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_add_del_session_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_add_del_session()
{
  static const char name[] = "classify_add_del_session";
  static const char name_with_crc[] = "classify_add_del_session_f20879f0";
  static vapi_message_desc_t __vapi_metadata_classify_add_del_session = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_add_del_session, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_add_del_session_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_add_del_session_hton,
    (generic_swap_fn_t)vapi_msg_classify_add_del_session_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_add_del_session = vapi_register_msg(&__vapi_metadata_classify_add_del_session);
  VAPI_DBG("Assigned msg id %d to classify_add_del_session", vapi_msg_id_classify_add_del_session);
}
#endif

#ifndef defined_vapi_msg_policer_classify_set_interface_reply
#define defined_vapi_msg_policer_classify_set_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_policer_classify_set_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_classify_set_interface_reply payload;
} vapi_msg_policer_classify_set_interface_reply;

static inline void vapi_msg_policer_classify_set_interface_reply_payload_hton(vapi_payload_policer_classify_set_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_policer_classify_set_interface_reply_payload_ntoh(vapi_payload_policer_classify_set_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_policer_classify_set_interface_reply_hton(vapi_msg_policer_classify_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_set_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_classify_set_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_classify_set_interface_reply_ntoh(vapi_msg_policer_classify_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_set_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_classify_set_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_classify_set_interface_reply_msg_size(vapi_msg_policer_classify_set_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_classify_set_interface_reply_msg_size(vapi_msg_policer_classify_set_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_classify_set_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_classify_set_interface_reply));
      return -1;
    }
  if (vapi_calc_policer_classify_set_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_classify_set_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_classify_set_interface_reply()
{
  static const char name[] = "policer_classify_set_interface_reply";
  static const char name_with_crc[] = "policer_classify_set_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_policer_classify_set_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_classify_set_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_classify_set_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_classify_set_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_policer_classify_set_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_classify_set_interface_reply = vapi_register_msg(&__vapi_metadata_policer_classify_set_interface_reply);
  VAPI_DBG("Assigned msg id %d to policer_classify_set_interface_reply", vapi_msg_id_policer_classify_set_interface_reply);
}

static inline void vapi_set_vapi_msg_policer_classify_set_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_classify_set_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_classify_set_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_classify_set_interface
#define defined_vapi_msg_policer_classify_set_interface
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 l2_table_index;
  bool is_add; 
} vapi_payload_policer_classify_set_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_classify_set_interface payload;
} vapi_msg_policer_classify_set_interface;

static inline void vapi_msg_policer_classify_set_interface_payload_hton(vapi_payload_policer_classify_set_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
  payload->l2_table_index = htobe32(payload->l2_table_index);
}

static inline void vapi_msg_policer_classify_set_interface_payload_ntoh(vapi_payload_policer_classify_set_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
  payload->l2_table_index = be32toh(payload->l2_table_index);
}

static inline void vapi_msg_policer_classify_set_interface_hton(vapi_msg_policer_classify_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_set_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_classify_set_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_classify_set_interface_ntoh(vapi_msg_policer_classify_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_set_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_classify_set_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_classify_set_interface_msg_size(vapi_msg_policer_classify_set_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_classify_set_interface_msg_size(vapi_msg_policer_classify_set_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_classify_set_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_classify_set_interface));
      return -1;
    }
  if (vapi_calc_policer_classify_set_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_classify_set_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_classify_set_interface* vapi_alloc_policer_classify_set_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_classify_set_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_classify_set_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_classify_set_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_classify_set_interface);

  return msg;
}

static inline vapi_error_e vapi_policer_classify_set_interface(struct vapi_ctx_s *ctx,
  vapi_msg_policer_classify_set_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_classify_set_interface_reply *reply),
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
  vapi_msg_policer_classify_set_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_classify_set_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_policer_classify_set_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_classify_set_interface()
{
  static const char name[] = "policer_classify_set_interface";
  static const char name_with_crc[] = "policer_classify_set_interface_de7ad708";
  static vapi_message_desc_t __vapi_metadata_policer_classify_set_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_classify_set_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_classify_set_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_classify_set_interface_hton,
    (generic_swap_fn_t)vapi_msg_policer_classify_set_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_classify_set_interface = vapi_register_msg(&__vapi_metadata_policer_classify_set_interface);
  VAPI_DBG("Assigned msg id %d to policer_classify_set_interface", vapi_msg_id_policer_classify_set_interface);
}
#endif

#ifndef defined_vapi_msg_policer_classify_details
#define defined_vapi_msg_policer_classify_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 table_index; 
} vapi_payload_policer_classify_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_policer_classify_details payload;
} vapi_msg_policer_classify_details;

static inline void vapi_msg_policer_classify_details_payload_hton(vapi_payload_policer_classify_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_policer_classify_details_payload_ntoh(vapi_payload_policer_classify_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_policer_classify_details_hton(vapi_msg_policer_classify_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_policer_classify_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_classify_details_ntoh(vapi_msg_policer_classify_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_policer_classify_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_classify_details_msg_size(vapi_msg_policer_classify_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_classify_details_msg_size(vapi_msg_policer_classify_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_classify_details) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_classify_details));
      return -1;
    }
  if (vapi_calc_policer_classify_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_classify_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_policer_classify_details()
{
  static const char name[] = "policer_classify_details";
  static const char name_with_crc[] = "policer_classify_details_dfd08765";
  static vapi_message_desc_t __vapi_metadata_policer_classify_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_policer_classify_details, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_classify_details_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_classify_details_hton,
    (generic_swap_fn_t)vapi_msg_policer_classify_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_classify_details = vapi_register_msg(&__vapi_metadata_policer_classify_details);
  VAPI_DBG("Assigned msg id %d to policer_classify_details", vapi_msg_id_policer_classify_details);
}

static inline void vapi_set_vapi_msg_policer_classify_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_policer_classify_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_policer_classify_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_policer_classify_dump
#define defined_vapi_msg_policer_classify_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_policer_classify_table type;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_policer_classify_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_policer_classify_dump payload;
} vapi_msg_policer_classify_dump;

static inline void vapi_msg_policer_classify_dump_payload_hton(vapi_payload_policer_classify_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_policer_classify_dump_payload_ntoh(vapi_payload_policer_classify_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_policer_classify_dump_hton(vapi_msg_policer_classify_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_policer_classify_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_policer_classify_dump_ntoh(vapi_msg_policer_classify_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_policer_classify_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_policer_classify_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_policer_classify_dump_msg_size(vapi_msg_policer_classify_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_policer_classify_dump_msg_size(vapi_msg_policer_classify_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_policer_classify_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_policer_classify_dump));
      return -1;
    }
  if (vapi_calc_policer_classify_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'policer_classify_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_policer_classify_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_policer_classify_dump* vapi_alloc_policer_classify_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_policer_classify_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_policer_classify_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_policer_classify_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_policer_classify_dump);

  return msg;
}

static inline vapi_error_e vapi_policer_classify_dump(struct vapi_ctx_s *ctx,
  vapi_msg_policer_classify_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_policer_classify_details *reply),
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
  vapi_msg_policer_classify_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_policer_classify_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_policer_classify_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_policer_classify_dump()
{
  static const char name[] = "policer_classify_dump";
  static const char name_with_crc[] = "policer_classify_dump_56cbb5fb";
  static vapi_message_desc_t __vapi_metadata_policer_classify_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_policer_classify_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_policer_classify_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_policer_classify_dump_hton,
    (generic_swap_fn_t)vapi_msg_policer_classify_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_policer_classify_dump = vapi_register_msg(&__vapi_metadata_policer_classify_dump);
  VAPI_DBG("Assigned msg id %d to policer_classify_dump", vapi_msg_id_policer_classify_dump);
}
#endif

#ifndef defined_vapi_msg_classify_table_ids_reply
#define defined_vapi_msg_classify_table_ids_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  u32 ids[0]; 
} vapi_payload_classify_table_ids_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_table_ids_reply payload;
} vapi_msg_classify_table_ids_reply;

static inline void vapi_msg_classify_table_ids_reply_payload_hton(vapi_payload_classify_table_ids_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->ids[i] = htobe32(payload->ids[i]); } } while(0);
}

static inline void vapi_msg_classify_table_ids_reply_payload_ntoh(vapi_payload_classify_table_ids_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->ids[i] = be32toh(payload->ids[i]); } } while(0);
}

static inline void vapi_msg_classify_table_ids_reply_hton(vapi_msg_classify_table_ids_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_ids_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_table_ids_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_table_ids_reply_ntoh(vapi_msg_classify_table_ids_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_ids_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_table_ids_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_table_ids_reply_msg_size(vapi_msg_classify_table_ids_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.ids[0]) * msg->payload.count;
}

static inline int vapi_verify_classify_table_ids_reply_msg_size(vapi_msg_classify_table_ids_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_ids_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_ids_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_ids_reply));
      return -1;
    }
  if (vapi_calc_classify_table_ids_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_ids_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_ids_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_table_ids_reply()
{
  static const char name[] = "classify_table_ids_reply";
  static const char name_with_crc[] = "classify_table_ids_reply_d1d20e1d";
  static vapi_message_desc_t __vapi_metadata_classify_table_ids_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_table_ids_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_table_ids_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_ids_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_ids_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_ids_reply = vapi_register_msg(&__vapi_metadata_classify_table_ids_reply);
  VAPI_DBG("Assigned msg id %d to classify_table_ids_reply", vapi_msg_id_classify_table_ids_reply);
}

static inline void vapi_set_vapi_msg_classify_table_ids_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_table_ids_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_table_ids_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_table_ids
#define defined_vapi_msg_classify_table_ids
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_classify_table_ids;

static inline void vapi_msg_classify_table_ids_hton(vapi_msg_classify_table_ids *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_ids'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_classify_table_ids_ntoh(vapi_msg_classify_table_ids *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_ids'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_classify_table_ids_msg_size(vapi_msg_classify_table_ids *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_table_ids_msg_size(vapi_msg_classify_table_ids *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_ids) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_ids' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_ids));
      return -1;
    }
  if (vapi_calc_classify_table_ids_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_ids' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_ids_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_table_ids* vapi_alloc_classify_table_ids(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_table_ids *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_table_ids);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_table_ids*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_table_ids);

  return msg;
}

static inline vapi_error_e vapi_classify_table_ids(struct vapi_ctx_s *ctx,
  vapi_msg_classify_table_ids *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_table_ids_reply *reply),
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
  vapi_msg_classify_table_ids_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_table_ids_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_table_ids_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_table_ids()
{
  static const char name[] = "classify_table_ids";
  static const char name_with_crc[] = "classify_table_ids_51077d14";
  static vapi_message_desc_t __vapi_metadata_classify_table_ids = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_classify_table_ids_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_ids_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_ids_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_ids = vapi_register_msg(&__vapi_metadata_classify_table_ids);
  VAPI_DBG("Assigned msg id %d to classify_table_ids", vapi_msg_id_classify_table_ids);
}
#endif

#ifndef defined_vapi_msg_classify_table_by_interface_reply
#define defined_vapi_msg_classify_table_by_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index;
  u32 l2_table_id;
  u32 ip4_table_id;
  u32 ip6_table_id; 
} vapi_payload_classify_table_by_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_table_by_interface_reply payload;
} vapi_msg_classify_table_by_interface_reply;

static inline void vapi_msg_classify_table_by_interface_reply_payload_hton(vapi_payload_classify_table_by_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->l2_table_id = htobe32(payload->l2_table_id);
  payload->ip4_table_id = htobe32(payload->ip4_table_id);
  payload->ip6_table_id = htobe32(payload->ip6_table_id);
}

static inline void vapi_msg_classify_table_by_interface_reply_payload_ntoh(vapi_payload_classify_table_by_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->l2_table_id = be32toh(payload->l2_table_id);
  payload->ip4_table_id = be32toh(payload->ip4_table_id);
  payload->ip6_table_id = be32toh(payload->ip6_table_id);
}

static inline void vapi_msg_classify_table_by_interface_reply_hton(vapi_msg_classify_table_by_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_by_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_table_by_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_table_by_interface_reply_ntoh(vapi_msg_classify_table_by_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_by_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_table_by_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_table_by_interface_reply_msg_size(vapi_msg_classify_table_by_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_table_by_interface_reply_msg_size(vapi_msg_classify_table_by_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_by_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_by_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_by_interface_reply));
      return -1;
    }
  if (vapi_calc_classify_table_by_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_by_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_by_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_table_by_interface_reply()
{
  static const char name[] = "classify_table_by_interface_reply";
  static const char name_with_crc[] = "classify_table_by_interface_reply_ed4197db";
  static vapi_message_desc_t __vapi_metadata_classify_table_by_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_table_by_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_table_by_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_by_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_by_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_by_interface_reply = vapi_register_msg(&__vapi_metadata_classify_table_by_interface_reply);
  VAPI_DBG("Assigned msg id %d to classify_table_by_interface_reply", vapi_msg_id_classify_table_by_interface_reply);
}

static inline void vapi_set_vapi_msg_classify_table_by_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_table_by_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_table_by_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_table_by_interface
#define defined_vapi_msg_classify_table_by_interface
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_classify_table_by_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_table_by_interface payload;
} vapi_msg_classify_table_by_interface;

static inline void vapi_msg_classify_table_by_interface_payload_hton(vapi_payload_classify_table_by_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_classify_table_by_interface_payload_ntoh(vapi_payload_classify_table_by_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_classify_table_by_interface_hton(vapi_msg_classify_table_by_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_by_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_table_by_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_table_by_interface_ntoh(vapi_msg_classify_table_by_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_by_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_table_by_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_table_by_interface_msg_size(vapi_msg_classify_table_by_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_table_by_interface_msg_size(vapi_msg_classify_table_by_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_by_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_by_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_by_interface));
      return -1;
    }
  if (vapi_calc_classify_table_by_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_by_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_by_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_table_by_interface* vapi_alloc_classify_table_by_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_table_by_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_table_by_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_table_by_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_table_by_interface);

  return msg;
}

static inline vapi_error_e vapi_classify_table_by_interface(struct vapi_ctx_s *ctx,
  vapi_msg_classify_table_by_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_table_by_interface_reply *reply),
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
  vapi_msg_classify_table_by_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_table_by_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_table_by_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_table_by_interface()
{
  static const char name[] = "classify_table_by_interface";
  static const char name_with_crc[] = "classify_table_by_interface_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_classify_table_by_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_table_by_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_table_by_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_by_interface_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_by_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_by_interface = vapi_register_msg(&__vapi_metadata_classify_table_by_interface);
  VAPI_DBG("Assigned msg id %d to classify_table_by_interface", vapi_msg_id_classify_table_by_interface);
}
#endif

#ifndef defined_vapi_msg_classify_table_info_reply
#define defined_vapi_msg_classify_table_info_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_id;
  u32 nbuckets;
  u32 match_n_vectors;
  u32 skip_n_vectors;
  u32 active_sessions;
  u32 next_table_index;
  u32 miss_next_index;
  u32 mask_length;
  u8 mask[0]; 
} vapi_payload_classify_table_info_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_table_info_reply payload;
} vapi_msg_classify_table_info_reply;

static inline void vapi_msg_classify_table_info_reply_payload_hton(vapi_payload_classify_table_info_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_id = htobe32(payload->table_id);
  payload->nbuckets = htobe32(payload->nbuckets);
  payload->match_n_vectors = htobe32(payload->match_n_vectors);
  payload->skip_n_vectors = htobe32(payload->skip_n_vectors);
  payload->active_sessions = htobe32(payload->active_sessions);
  payload->next_table_index = htobe32(payload->next_table_index);
  payload->miss_next_index = htobe32(payload->miss_next_index);
  payload->mask_length = htobe32(payload->mask_length);
}

static inline void vapi_msg_classify_table_info_reply_payload_ntoh(vapi_payload_classify_table_info_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_id = be32toh(payload->table_id);
  payload->nbuckets = be32toh(payload->nbuckets);
  payload->match_n_vectors = be32toh(payload->match_n_vectors);
  payload->skip_n_vectors = be32toh(payload->skip_n_vectors);
  payload->active_sessions = be32toh(payload->active_sessions);
  payload->next_table_index = be32toh(payload->next_table_index);
  payload->miss_next_index = be32toh(payload->miss_next_index);
  payload->mask_length = be32toh(payload->mask_length);
}

static inline void vapi_msg_classify_table_info_reply_hton(vapi_msg_classify_table_info_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_info_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_table_info_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_table_info_reply_ntoh(vapi_msg_classify_table_info_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_info_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_table_info_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_table_info_reply_msg_size(vapi_msg_classify_table_info_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.mask[0]) * msg->payload.mask_length;
}

static inline int vapi_verify_classify_table_info_reply_msg_size(vapi_msg_classify_table_info_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_info_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_info_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_info_reply));
      return -1;
    }
  if (vapi_calc_classify_table_info_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_info_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_info_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_table_info_reply()
{
  static const char name[] = "classify_table_info_reply";
  static const char name_with_crc[] = "classify_table_info_reply_4a573c0e";
  static vapi_message_desc_t __vapi_metadata_classify_table_info_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_table_info_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_table_info_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_info_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_info_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_info_reply = vapi_register_msg(&__vapi_metadata_classify_table_info_reply);
  VAPI_DBG("Assigned msg id %d to classify_table_info_reply", vapi_msg_id_classify_table_info_reply);
}

static inline void vapi_set_vapi_msg_classify_table_info_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_table_info_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_table_info_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_table_info
#define defined_vapi_msg_classify_table_info
typedef struct __attribute__ ((__packed__)) {
  u32 table_id; 
} vapi_payload_classify_table_info;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_table_info payload;
} vapi_msg_classify_table_info;

static inline void vapi_msg_classify_table_info_payload_hton(vapi_payload_classify_table_info *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_classify_table_info_payload_ntoh(vapi_payload_classify_table_info *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_classify_table_info_hton(vapi_msg_classify_table_info *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_info'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_table_info_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_table_info_ntoh(vapi_msg_classify_table_info *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_table_info'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_table_info_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_table_info_msg_size(vapi_msg_classify_table_info *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_table_info_msg_size(vapi_msg_classify_table_info *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_table_info) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_info' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_table_info));
      return -1;
    }
  if (vapi_calc_classify_table_info_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_table_info' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_table_info_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_table_info* vapi_alloc_classify_table_info(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_table_info *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_table_info);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_table_info*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_table_info);

  return msg;
}

static inline vapi_error_e vapi_classify_table_info(struct vapi_ctx_s *ctx,
  vapi_msg_classify_table_info *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_table_info_reply *reply),
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
  vapi_msg_classify_table_info_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_table_info_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_table_info_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_table_info()
{
  static const char name[] = "classify_table_info";
  static const char name_with_crc[] = "classify_table_info_0cca2cd9";
  static vapi_message_desc_t __vapi_metadata_classify_table_info = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_table_info, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_table_info_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_table_info_hton,
    (generic_swap_fn_t)vapi_msg_classify_table_info_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_table_info = vapi_register_msg(&__vapi_metadata_classify_table_info);
  VAPI_DBG("Assigned msg id %d to classify_table_info", vapi_msg_id_classify_table_info);
}
#endif

#ifndef defined_vapi_msg_classify_session_details
#define defined_vapi_msg_classify_session_details
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_id;
  u32 hit_next_index;
  i32 advance;
  u32 opaque_index;
  u32 match_length;
  u8 match[0]; 
} vapi_payload_classify_session_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_session_details payload;
} vapi_msg_classify_session_details;

static inline void vapi_msg_classify_session_details_payload_hton(vapi_payload_classify_session_details *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_id = htobe32(payload->table_id);
  payload->hit_next_index = htobe32(payload->hit_next_index);
  payload->advance = htobe32(payload->advance);
  payload->opaque_index = htobe32(payload->opaque_index);
  payload->match_length = htobe32(payload->match_length);
}

static inline void vapi_msg_classify_session_details_payload_ntoh(vapi_payload_classify_session_details *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_id = be32toh(payload->table_id);
  payload->hit_next_index = be32toh(payload->hit_next_index);
  payload->advance = be32toh(payload->advance);
  payload->opaque_index = be32toh(payload->opaque_index);
  payload->match_length = be32toh(payload->match_length);
}

static inline void vapi_msg_classify_session_details_hton(vapi_msg_classify_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_session_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_session_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_session_details_ntoh(vapi_msg_classify_session_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_session_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_session_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_session_details_msg_size(vapi_msg_classify_session_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.match[0]) * msg->payload.match_length;
}

static inline int vapi_verify_classify_session_details_msg_size(vapi_msg_classify_session_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_session_details) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_session_details));
      return -1;
    }
  if (vapi_calc_classify_session_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_session_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_session_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_session_details()
{
  static const char name[] = "classify_session_details";
  static const char name_with_crc[] = "classify_session_details_60e3ef94";
  static vapi_message_desc_t __vapi_metadata_classify_session_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_session_details, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_session_details_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_session_details_hton,
    (generic_swap_fn_t)vapi_msg_classify_session_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_session_details = vapi_register_msg(&__vapi_metadata_classify_session_details);
  VAPI_DBG("Assigned msg id %d to classify_session_details", vapi_msg_id_classify_session_details);
}

static inline void vapi_set_vapi_msg_classify_session_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_session_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_session_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_session_dump
#define defined_vapi_msg_classify_session_dump
typedef struct __attribute__ ((__packed__)) {
  u32 table_id; 
} vapi_payload_classify_session_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_session_dump payload;
} vapi_msg_classify_session_dump;

static inline void vapi_msg_classify_session_dump_payload_hton(vapi_payload_classify_session_dump *payload)
{
  payload->table_id = htobe32(payload->table_id);
}

static inline void vapi_msg_classify_session_dump_payload_ntoh(vapi_payload_classify_session_dump *payload)
{
  payload->table_id = be32toh(payload->table_id);
}

static inline void vapi_msg_classify_session_dump_hton(vapi_msg_classify_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_session_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_session_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_session_dump_ntoh(vapi_msg_classify_session_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_session_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_session_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_session_dump_msg_size(vapi_msg_classify_session_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_session_dump_msg_size(vapi_msg_classify_session_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_session_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_session_dump));
      return -1;
    }
  if (vapi_calc_classify_session_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_session_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_session_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_session_dump* vapi_alloc_classify_session_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_session_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_session_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_session_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_session_dump);

  return msg;
}

static inline vapi_error_e vapi_classify_session_dump(struct vapi_ctx_s *ctx,
  vapi_msg_classify_session_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_session_details *reply),
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
  vapi_msg_classify_session_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_session_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_classify_session_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_session_dump()
{
  static const char name[] = "classify_session_dump";
  static const char name_with_crc[] = "classify_session_dump_0cca2cd9";
  static vapi_message_desc_t __vapi_metadata_classify_session_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_session_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_session_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_session_dump_hton,
    (generic_swap_fn_t)vapi_msg_classify_session_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_session_dump = vapi_register_msg(&__vapi_metadata_classify_session_dump);
  VAPI_DBG("Assigned msg id %d to classify_session_dump", vapi_msg_id_classify_session_dump);
}
#endif

#ifndef defined_vapi_msg_flow_classify_set_interface_reply
#define defined_vapi_msg_flow_classify_set_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_flow_classify_set_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_classify_set_interface_reply payload;
} vapi_msg_flow_classify_set_interface_reply;

static inline void vapi_msg_flow_classify_set_interface_reply_payload_hton(vapi_payload_flow_classify_set_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_flow_classify_set_interface_reply_payload_ntoh(vapi_payload_flow_classify_set_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_flow_classify_set_interface_reply_hton(vapi_msg_flow_classify_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_set_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_classify_set_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_classify_set_interface_reply_ntoh(vapi_msg_flow_classify_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_set_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_classify_set_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_classify_set_interface_reply_msg_size(vapi_msg_flow_classify_set_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_classify_set_interface_reply_msg_size(vapi_msg_flow_classify_set_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_classify_set_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_classify_set_interface_reply));
      return -1;
    }
  if (vapi_calc_flow_classify_set_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_classify_set_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_classify_set_interface_reply()
{
  static const char name[] = "flow_classify_set_interface_reply";
  static const char name_with_crc[] = "flow_classify_set_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_flow_classify_set_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_classify_set_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_classify_set_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_classify_set_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_flow_classify_set_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_classify_set_interface_reply = vapi_register_msg(&__vapi_metadata_flow_classify_set_interface_reply);
  VAPI_DBG("Assigned msg id %d to flow_classify_set_interface_reply", vapi_msg_id_flow_classify_set_interface_reply);
}

static inline void vapi_set_vapi_msg_flow_classify_set_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_classify_set_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_classify_set_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_classify_set_interface
#define defined_vapi_msg_flow_classify_set_interface
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 ip4_table_index;
  u32 ip6_table_index;
  bool is_add; 
} vapi_payload_flow_classify_set_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_classify_set_interface payload;
} vapi_msg_flow_classify_set_interface;

static inline void vapi_msg_flow_classify_set_interface_payload_hton(vapi_payload_flow_classify_set_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
}

static inline void vapi_msg_flow_classify_set_interface_payload_ntoh(vapi_payload_flow_classify_set_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
}

static inline void vapi_msg_flow_classify_set_interface_hton(vapi_msg_flow_classify_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_set_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_classify_set_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_classify_set_interface_ntoh(vapi_msg_flow_classify_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_set_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_classify_set_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_classify_set_interface_msg_size(vapi_msg_flow_classify_set_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_classify_set_interface_msg_size(vapi_msg_flow_classify_set_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_classify_set_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_classify_set_interface));
      return -1;
    }
  if (vapi_calc_flow_classify_set_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_classify_set_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_classify_set_interface* vapi_alloc_flow_classify_set_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_classify_set_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_classify_set_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_classify_set_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_classify_set_interface);

  return msg;
}

static inline vapi_error_e vapi_flow_classify_set_interface(struct vapi_ctx_s *ctx,
  vapi_msg_flow_classify_set_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_classify_set_interface_reply *reply),
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
  vapi_msg_flow_classify_set_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_classify_set_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_flow_classify_set_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_classify_set_interface()
{
  static const char name[] = "flow_classify_set_interface";
  static const char name_with_crc[] = "flow_classify_set_interface_b6192f1c";
  static vapi_message_desc_t __vapi_metadata_flow_classify_set_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_classify_set_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_classify_set_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_classify_set_interface_hton,
    (generic_swap_fn_t)vapi_msg_flow_classify_set_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_classify_set_interface = vapi_register_msg(&__vapi_metadata_flow_classify_set_interface);
  VAPI_DBG("Assigned msg id %d to flow_classify_set_interface", vapi_msg_id_flow_classify_set_interface);
}
#endif

#ifndef defined_vapi_msg_flow_classify_details
#define defined_vapi_msg_flow_classify_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 table_index; 
} vapi_payload_flow_classify_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_flow_classify_details payload;
} vapi_msg_flow_classify_details;

static inline void vapi_msg_flow_classify_details_payload_hton(vapi_payload_flow_classify_details *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_flow_classify_details_payload_ntoh(vapi_payload_flow_classify_details *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_flow_classify_details_hton(vapi_msg_flow_classify_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_flow_classify_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_classify_details_ntoh(vapi_msg_flow_classify_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_flow_classify_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_classify_details_msg_size(vapi_msg_flow_classify_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_classify_details_msg_size(vapi_msg_flow_classify_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_classify_details) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_classify_details));
      return -1;
    }
  if (vapi_calc_flow_classify_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_classify_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_flow_classify_details()
{
  static const char name[] = "flow_classify_details";
  static const char name_with_crc[] = "flow_classify_details_dfd08765";
  static vapi_message_desc_t __vapi_metadata_flow_classify_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_flow_classify_details, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_classify_details_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_classify_details_hton,
    (generic_swap_fn_t)vapi_msg_flow_classify_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_classify_details = vapi_register_msg(&__vapi_metadata_flow_classify_details);
  VAPI_DBG("Assigned msg id %d to flow_classify_details", vapi_msg_id_flow_classify_details);
}

static inline void vapi_set_vapi_msg_flow_classify_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_flow_classify_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_flow_classify_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_flow_classify_dump
#define defined_vapi_msg_flow_classify_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_flow_classify_table type;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_flow_classify_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_flow_classify_dump payload;
} vapi_msg_flow_classify_dump;

static inline void vapi_msg_flow_classify_dump_payload_hton(vapi_payload_flow_classify_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_flow_classify_dump_payload_ntoh(vapi_payload_flow_classify_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_flow_classify_dump_hton(vapi_msg_flow_classify_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_flow_classify_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_flow_classify_dump_ntoh(vapi_msg_flow_classify_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_flow_classify_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_flow_classify_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_flow_classify_dump_msg_size(vapi_msg_flow_classify_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_flow_classify_dump_msg_size(vapi_msg_flow_classify_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_flow_classify_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_flow_classify_dump));
      return -1;
    }
  if (vapi_calc_flow_classify_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'flow_classify_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_flow_classify_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_flow_classify_dump* vapi_alloc_flow_classify_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_flow_classify_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_flow_classify_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_flow_classify_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_flow_classify_dump);

  return msg;
}

static inline vapi_error_e vapi_flow_classify_dump(struct vapi_ctx_s *ctx,
  vapi_msg_flow_classify_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_flow_classify_details *reply),
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
  vapi_msg_flow_classify_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_flow_classify_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_flow_classify_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_flow_classify_dump()
{
  static const char name[] = "flow_classify_dump";
  static const char name_with_crc[] = "flow_classify_dump_25dd3e4c";
  static vapi_message_desc_t __vapi_metadata_flow_classify_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_flow_classify_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_flow_classify_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_flow_classify_dump_hton,
    (generic_swap_fn_t)vapi_msg_flow_classify_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_flow_classify_dump = vapi_register_msg(&__vapi_metadata_flow_classify_dump);
  VAPI_DBG("Assigned msg id %d to flow_classify_dump", vapi_msg_id_flow_classify_dump);
}
#endif

#ifndef defined_vapi_msg_classify_set_interface_ip_table_reply
#define defined_vapi_msg_classify_set_interface_ip_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_classify_set_interface_ip_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_set_interface_ip_table_reply payload;
} vapi_msg_classify_set_interface_ip_table_reply;

static inline void vapi_msg_classify_set_interface_ip_table_reply_payload_hton(vapi_payload_classify_set_interface_ip_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_classify_set_interface_ip_table_reply_payload_ntoh(vapi_payload_classify_set_interface_ip_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_classify_set_interface_ip_table_reply_hton(vapi_msg_classify_set_interface_ip_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_ip_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_set_interface_ip_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_set_interface_ip_table_reply_ntoh(vapi_msg_classify_set_interface_ip_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_ip_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_set_interface_ip_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_set_interface_ip_table_reply_msg_size(vapi_msg_classify_set_interface_ip_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_set_interface_ip_table_reply_msg_size(vapi_msg_classify_set_interface_ip_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_set_interface_ip_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_ip_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_set_interface_ip_table_reply));
      return -1;
    }
  if (vapi_calc_classify_set_interface_ip_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_ip_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_set_interface_ip_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_set_interface_ip_table_reply()
{
  static const char name[] = "classify_set_interface_ip_table_reply";
  static const char name_with_crc[] = "classify_set_interface_ip_table_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_classify_set_interface_ip_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_set_interface_ip_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_set_interface_ip_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_ip_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_ip_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_set_interface_ip_table_reply = vapi_register_msg(&__vapi_metadata_classify_set_interface_ip_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_set_interface_ip_table_reply", vapi_msg_id_classify_set_interface_ip_table_reply);
}

static inline void vapi_set_vapi_msg_classify_set_interface_ip_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_set_interface_ip_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_set_interface_ip_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_set_interface_ip_table
#define defined_vapi_msg_classify_set_interface_ip_table
typedef struct __attribute__ ((__packed__)) {
  bool is_ipv6;
  vapi_type_interface_index sw_if_index;
  u32 table_index; 
} vapi_payload_classify_set_interface_ip_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_set_interface_ip_table payload;
} vapi_msg_classify_set_interface_ip_table;

static inline void vapi_msg_classify_set_interface_ip_table_payload_hton(vapi_payload_classify_set_interface_ip_table *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_set_interface_ip_table_payload_ntoh(vapi_payload_classify_set_interface_ip_table *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_set_interface_ip_table_hton(vapi_msg_classify_set_interface_ip_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_ip_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_set_interface_ip_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_set_interface_ip_table_ntoh(vapi_msg_classify_set_interface_ip_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_ip_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_set_interface_ip_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_set_interface_ip_table_msg_size(vapi_msg_classify_set_interface_ip_table *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_set_interface_ip_table_msg_size(vapi_msg_classify_set_interface_ip_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_set_interface_ip_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_ip_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_set_interface_ip_table));
      return -1;
    }
  if (vapi_calc_classify_set_interface_ip_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_ip_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_set_interface_ip_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_set_interface_ip_table* vapi_alloc_classify_set_interface_ip_table(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_set_interface_ip_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_set_interface_ip_table);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_set_interface_ip_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_set_interface_ip_table);

  return msg;
}

static inline vapi_error_e vapi_classify_set_interface_ip_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_set_interface_ip_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_set_interface_ip_table_reply *reply),
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
  vapi_msg_classify_set_interface_ip_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_set_interface_ip_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_set_interface_ip_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_set_interface_ip_table()
{
  static const char name[] = "classify_set_interface_ip_table";
  static const char name_with_crc[] = "classify_set_interface_ip_table_e0b097c7";
  static vapi_message_desc_t __vapi_metadata_classify_set_interface_ip_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_set_interface_ip_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_set_interface_ip_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_ip_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_ip_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_set_interface_ip_table = vapi_register_msg(&__vapi_metadata_classify_set_interface_ip_table);
  VAPI_DBG("Assigned msg id %d to classify_set_interface_ip_table", vapi_msg_id_classify_set_interface_ip_table);
}
#endif

#ifndef defined_vapi_msg_classify_set_interface_l2_tables_reply
#define defined_vapi_msg_classify_set_interface_l2_tables_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_classify_set_interface_l2_tables_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_set_interface_l2_tables_reply payload;
} vapi_msg_classify_set_interface_l2_tables_reply;

static inline void vapi_msg_classify_set_interface_l2_tables_reply_payload_hton(vapi_payload_classify_set_interface_l2_tables_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_classify_set_interface_l2_tables_reply_payload_ntoh(vapi_payload_classify_set_interface_l2_tables_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_classify_set_interface_l2_tables_reply_hton(vapi_msg_classify_set_interface_l2_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_l2_tables_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_set_interface_l2_tables_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_set_interface_l2_tables_reply_ntoh(vapi_msg_classify_set_interface_l2_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_l2_tables_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_set_interface_l2_tables_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_set_interface_l2_tables_reply_msg_size(vapi_msg_classify_set_interface_l2_tables_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_set_interface_l2_tables_reply_msg_size(vapi_msg_classify_set_interface_l2_tables_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_set_interface_l2_tables_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_l2_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_set_interface_l2_tables_reply));
      return -1;
    }
  if (vapi_calc_classify_set_interface_l2_tables_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_l2_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_set_interface_l2_tables_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_set_interface_l2_tables_reply()
{
  static const char name[] = "classify_set_interface_l2_tables_reply";
  static const char name_with_crc[] = "classify_set_interface_l2_tables_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_classify_set_interface_l2_tables_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_set_interface_l2_tables_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_set_interface_l2_tables_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_l2_tables_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_l2_tables_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_set_interface_l2_tables_reply = vapi_register_msg(&__vapi_metadata_classify_set_interface_l2_tables_reply);
  VAPI_DBG("Assigned msg id %d to classify_set_interface_l2_tables_reply", vapi_msg_id_classify_set_interface_l2_tables_reply);
}

static inline void vapi_set_vapi_msg_classify_set_interface_l2_tables_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_set_interface_l2_tables_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_set_interface_l2_tables_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_set_interface_l2_tables
#define defined_vapi_msg_classify_set_interface_l2_tables
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 other_table_index;
  bool is_input; 
} vapi_payload_classify_set_interface_l2_tables;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_set_interface_l2_tables payload;
} vapi_msg_classify_set_interface_l2_tables;

static inline void vapi_msg_classify_set_interface_l2_tables_payload_hton(vapi_payload_classify_set_interface_l2_tables *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
  payload->other_table_index = htobe32(payload->other_table_index);
}

static inline void vapi_msg_classify_set_interface_l2_tables_payload_ntoh(vapi_payload_classify_set_interface_l2_tables *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
  payload->other_table_index = be32toh(payload->other_table_index);
}

static inline void vapi_msg_classify_set_interface_l2_tables_hton(vapi_msg_classify_set_interface_l2_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_l2_tables'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_set_interface_l2_tables_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_set_interface_l2_tables_ntoh(vapi_msg_classify_set_interface_l2_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_set_interface_l2_tables'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_set_interface_l2_tables_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_set_interface_l2_tables_msg_size(vapi_msg_classify_set_interface_l2_tables *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_set_interface_l2_tables_msg_size(vapi_msg_classify_set_interface_l2_tables *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_set_interface_l2_tables) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_l2_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_set_interface_l2_tables));
      return -1;
    }
  if (vapi_calc_classify_set_interface_l2_tables_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_set_interface_l2_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_set_interface_l2_tables_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_set_interface_l2_tables* vapi_alloc_classify_set_interface_l2_tables(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_set_interface_l2_tables *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_set_interface_l2_tables);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_set_interface_l2_tables*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_set_interface_l2_tables);

  return msg;
}

static inline vapi_error_e vapi_classify_set_interface_l2_tables(struct vapi_ctx_s *ctx,
  vapi_msg_classify_set_interface_l2_tables *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_set_interface_l2_tables_reply *reply),
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
  vapi_msg_classify_set_interface_l2_tables_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_set_interface_l2_tables_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_set_interface_l2_tables_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_set_interface_l2_tables()
{
  static const char name[] = "classify_set_interface_l2_tables";
  static const char name_with_crc[] = "classify_set_interface_l2_tables_5a6ddf65";
  static vapi_message_desc_t __vapi_metadata_classify_set_interface_l2_tables = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_set_interface_l2_tables, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_set_interface_l2_tables_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_l2_tables_hton,
    (generic_swap_fn_t)vapi_msg_classify_set_interface_l2_tables_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_set_interface_l2_tables = vapi_register_msg(&__vapi_metadata_classify_set_interface_l2_tables);
  VAPI_DBG("Assigned msg id %d to classify_set_interface_l2_tables", vapi_msg_id_classify_set_interface_l2_tables);
}
#endif

#ifndef defined_vapi_msg_input_acl_set_interface_reply
#define defined_vapi_msg_input_acl_set_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_input_acl_set_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_input_acl_set_interface_reply payload;
} vapi_msg_input_acl_set_interface_reply;

static inline void vapi_msg_input_acl_set_interface_reply_payload_hton(vapi_payload_input_acl_set_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_input_acl_set_interface_reply_payload_ntoh(vapi_payload_input_acl_set_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_input_acl_set_interface_reply_hton(vapi_msg_input_acl_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_input_acl_set_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_input_acl_set_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_input_acl_set_interface_reply_ntoh(vapi_msg_input_acl_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_input_acl_set_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_input_acl_set_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_input_acl_set_interface_reply_msg_size(vapi_msg_input_acl_set_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_input_acl_set_interface_reply_msg_size(vapi_msg_input_acl_set_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_input_acl_set_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'input_acl_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_input_acl_set_interface_reply));
      return -1;
    }
  if (vapi_calc_input_acl_set_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'input_acl_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_input_acl_set_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_input_acl_set_interface_reply()
{
  static const char name[] = "input_acl_set_interface_reply";
  static const char name_with_crc[] = "input_acl_set_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_input_acl_set_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_input_acl_set_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_input_acl_set_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_input_acl_set_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_input_acl_set_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_input_acl_set_interface_reply = vapi_register_msg(&__vapi_metadata_input_acl_set_interface_reply);
  VAPI_DBG("Assigned msg id %d to input_acl_set_interface_reply", vapi_msg_id_input_acl_set_interface_reply);
}

static inline void vapi_set_vapi_msg_input_acl_set_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_input_acl_set_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_input_acl_set_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_input_acl_set_interface
#define defined_vapi_msg_input_acl_set_interface
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 l2_table_index;
  bool is_add; 
} vapi_payload_input_acl_set_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_input_acl_set_interface payload;
} vapi_msg_input_acl_set_interface;

static inline void vapi_msg_input_acl_set_interface_payload_hton(vapi_payload_input_acl_set_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
  payload->l2_table_index = htobe32(payload->l2_table_index);
}

static inline void vapi_msg_input_acl_set_interface_payload_ntoh(vapi_payload_input_acl_set_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
  payload->l2_table_index = be32toh(payload->l2_table_index);
}

static inline void vapi_msg_input_acl_set_interface_hton(vapi_msg_input_acl_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_input_acl_set_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_input_acl_set_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_input_acl_set_interface_ntoh(vapi_msg_input_acl_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_input_acl_set_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_input_acl_set_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_input_acl_set_interface_msg_size(vapi_msg_input_acl_set_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_input_acl_set_interface_msg_size(vapi_msg_input_acl_set_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_input_acl_set_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'input_acl_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_input_acl_set_interface));
      return -1;
    }
  if (vapi_calc_input_acl_set_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'input_acl_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_input_acl_set_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_input_acl_set_interface* vapi_alloc_input_acl_set_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_input_acl_set_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_input_acl_set_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_input_acl_set_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_input_acl_set_interface);

  return msg;
}

static inline vapi_error_e vapi_input_acl_set_interface(struct vapi_ctx_s *ctx,
  vapi_msg_input_acl_set_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_input_acl_set_interface_reply *reply),
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
  vapi_msg_input_acl_set_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_input_acl_set_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_input_acl_set_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_input_acl_set_interface()
{
  static const char name[] = "input_acl_set_interface";
  static const char name_with_crc[] = "input_acl_set_interface_de7ad708";
  static vapi_message_desc_t __vapi_metadata_input_acl_set_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_input_acl_set_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_input_acl_set_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_input_acl_set_interface_hton,
    (generic_swap_fn_t)vapi_msg_input_acl_set_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_input_acl_set_interface = vapi_register_msg(&__vapi_metadata_input_acl_set_interface);
  VAPI_DBG("Assigned msg id %d to input_acl_set_interface", vapi_msg_id_input_acl_set_interface);
}
#endif

#ifndef defined_vapi_msg_punt_acl_add_del_reply
#define defined_vapi_msg_punt_acl_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_punt_acl_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_punt_acl_add_del_reply payload;
} vapi_msg_punt_acl_add_del_reply;

static inline void vapi_msg_punt_acl_add_del_reply_payload_hton(vapi_payload_punt_acl_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_punt_acl_add_del_reply_payload_ntoh(vapi_payload_punt_acl_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_punt_acl_add_del_reply_hton(vapi_msg_punt_acl_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_punt_acl_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_acl_add_del_reply_ntoh(vapi_msg_punt_acl_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_punt_acl_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_acl_add_del_reply_msg_size(vapi_msg_punt_acl_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_acl_add_del_reply_msg_size(vapi_msg_punt_acl_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_acl_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_acl_add_del_reply));
      return -1;
    }
  if (vapi_calc_punt_acl_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_acl_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_punt_acl_add_del_reply()
{
  static const char name[] = "punt_acl_add_del_reply";
  static const char name_with_crc[] = "punt_acl_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_punt_acl_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_punt_acl_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_acl_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_acl_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_punt_acl_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_acl_add_del_reply = vapi_register_msg(&__vapi_metadata_punt_acl_add_del_reply);
  VAPI_DBG("Assigned msg id %d to punt_acl_add_del_reply", vapi_msg_id_punt_acl_add_del_reply);
}

static inline void vapi_set_vapi_msg_punt_acl_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_punt_acl_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_punt_acl_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_punt_acl_add_del
#define defined_vapi_msg_punt_acl_add_del
typedef struct __attribute__ ((__packed__)) {
  u32 ip4_table_index;
  u32 ip6_table_index;
  bool is_add; 
} vapi_payload_punt_acl_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_punt_acl_add_del payload;
} vapi_msg_punt_acl_add_del;

static inline void vapi_msg_punt_acl_add_del_payload_hton(vapi_payload_punt_acl_add_del *payload)
{
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
}

static inline void vapi_msg_punt_acl_add_del_payload_ntoh(vapi_payload_punt_acl_add_del *payload)
{
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
}

static inline void vapi_msg_punt_acl_add_del_hton(vapi_msg_punt_acl_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_punt_acl_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_acl_add_del_ntoh(vapi_msg_punt_acl_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_punt_acl_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_acl_add_del_msg_size(vapi_msg_punt_acl_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_acl_add_del_msg_size(vapi_msg_punt_acl_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_acl_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_acl_add_del));
      return -1;
    }
  if (vapi_calc_punt_acl_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_acl_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_punt_acl_add_del* vapi_alloc_punt_acl_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_punt_acl_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_punt_acl_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_punt_acl_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_punt_acl_add_del);

  return msg;
}

static inline vapi_error_e vapi_punt_acl_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_punt_acl_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_punt_acl_add_del_reply *reply),
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
  vapi_msg_punt_acl_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_punt_acl_add_del_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_punt_acl_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_punt_acl_add_del()
{
  static const char name[] = "punt_acl_add_del";
  static const char name_with_crc[] = "punt_acl_add_del_a93bf3a0";
  static vapi_message_desc_t __vapi_metadata_punt_acl_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_punt_acl_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_acl_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_acl_add_del_hton,
    (generic_swap_fn_t)vapi_msg_punt_acl_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_acl_add_del = vapi_register_msg(&__vapi_metadata_punt_acl_add_del);
  VAPI_DBG("Assigned msg id %d to punt_acl_add_del", vapi_msg_id_punt_acl_add_del);
}
#endif

#ifndef defined_vapi_msg_punt_acl_get_reply
#define defined_vapi_msg_punt_acl_get_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 ip4_table_index;
  u32 ip6_table_index; 
} vapi_payload_punt_acl_get_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_punt_acl_get_reply payload;
} vapi_msg_punt_acl_get_reply;

static inline void vapi_msg_punt_acl_get_reply_payload_hton(vapi_payload_punt_acl_get_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
}

static inline void vapi_msg_punt_acl_get_reply_payload_ntoh(vapi_payload_punt_acl_get_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
}

static inline void vapi_msg_punt_acl_get_reply_hton(vapi_msg_punt_acl_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_get_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_punt_acl_get_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_punt_acl_get_reply_ntoh(vapi_msg_punt_acl_get_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_get_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_punt_acl_get_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_punt_acl_get_reply_msg_size(vapi_msg_punt_acl_get_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_acl_get_reply_msg_size(vapi_msg_punt_acl_get_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_acl_get_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_acl_get_reply));
      return -1;
    }
  if (vapi_calc_punt_acl_get_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_get_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_acl_get_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_punt_acl_get_reply()
{
  static const char name[] = "punt_acl_get_reply";
  static const char name_with_crc[] = "punt_acl_get_reply_8409b9dd";
  static vapi_message_desc_t __vapi_metadata_punt_acl_get_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_punt_acl_get_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_punt_acl_get_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_acl_get_reply_hton,
    (generic_swap_fn_t)vapi_msg_punt_acl_get_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_acl_get_reply = vapi_register_msg(&__vapi_metadata_punt_acl_get_reply);
  VAPI_DBG("Assigned msg id %d to punt_acl_get_reply", vapi_msg_id_punt_acl_get_reply);
}

static inline void vapi_set_vapi_msg_punt_acl_get_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_punt_acl_get_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_punt_acl_get_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_punt_acl_get
#define defined_vapi_msg_punt_acl_get
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_punt_acl_get;

static inline void vapi_msg_punt_acl_get_hton(vapi_msg_punt_acl_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_get'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_punt_acl_get_ntoh(vapi_msg_punt_acl_get *msg)
{
  VAPI_DBG("Swapping `vapi_msg_punt_acl_get'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_punt_acl_get_msg_size(vapi_msg_punt_acl_get *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_punt_acl_get_msg_size(vapi_msg_punt_acl_get *msg, uword buf_size)
{
  if (sizeof(vapi_msg_punt_acl_get) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_punt_acl_get));
      return -1;
    }
  if (vapi_calc_punt_acl_get_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'punt_acl_get' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_punt_acl_get_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_punt_acl_get* vapi_alloc_punt_acl_get(struct vapi_ctx_s *ctx)
{
  vapi_msg_punt_acl_get *msg = NULL;
  const size_t size = sizeof(vapi_msg_punt_acl_get);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_punt_acl_get*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_punt_acl_get);

  return msg;
}

static inline vapi_error_e vapi_punt_acl_get(struct vapi_ctx_s *ctx,
  vapi_msg_punt_acl_get *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_punt_acl_get_reply *reply),
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
  vapi_msg_punt_acl_get_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_punt_acl_get_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_punt_acl_get_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_punt_acl_get()
{
  static const char name[] = "punt_acl_get";
  static const char name_with_crc[] = "punt_acl_get_51077d14";
  static vapi_message_desc_t __vapi_metadata_punt_acl_get = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_punt_acl_get_msg_size,
    (generic_swap_fn_t)vapi_msg_punt_acl_get_hton,
    (generic_swap_fn_t)vapi_msg_punt_acl_get_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_punt_acl_get = vapi_register_msg(&__vapi_metadata_punt_acl_get);
  VAPI_DBG("Assigned msg id %d to punt_acl_get", vapi_msg_id_punt_acl_get);
}
#endif

#ifndef defined_vapi_msg_output_acl_set_interface_reply
#define defined_vapi_msg_output_acl_set_interface_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_output_acl_set_interface_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_output_acl_set_interface_reply payload;
} vapi_msg_output_acl_set_interface_reply;

static inline void vapi_msg_output_acl_set_interface_reply_payload_hton(vapi_payload_output_acl_set_interface_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_output_acl_set_interface_reply_payload_ntoh(vapi_payload_output_acl_set_interface_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_output_acl_set_interface_reply_hton(vapi_msg_output_acl_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_output_acl_set_interface_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_output_acl_set_interface_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_output_acl_set_interface_reply_ntoh(vapi_msg_output_acl_set_interface_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_output_acl_set_interface_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_output_acl_set_interface_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_output_acl_set_interface_reply_msg_size(vapi_msg_output_acl_set_interface_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_output_acl_set_interface_reply_msg_size(vapi_msg_output_acl_set_interface_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_output_acl_set_interface_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'output_acl_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_output_acl_set_interface_reply));
      return -1;
    }
  if (vapi_calc_output_acl_set_interface_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'output_acl_set_interface_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_output_acl_set_interface_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_output_acl_set_interface_reply()
{
  static const char name[] = "output_acl_set_interface_reply";
  static const char name_with_crc[] = "output_acl_set_interface_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_output_acl_set_interface_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_output_acl_set_interface_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_output_acl_set_interface_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_output_acl_set_interface_reply_hton,
    (generic_swap_fn_t)vapi_msg_output_acl_set_interface_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_output_acl_set_interface_reply = vapi_register_msg(&__vapi_metadata_output_acl_set_interface_reply);
  VAPI_DBG("Assigned msg id %d to output_acl_set_interface_reply", vapi_msg_id_output_acl_set_interface_reply);
}

static inline void vapi_set_vapi_msg_output_acl_set_interface_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_output_acl_set_interface_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_output_acl_set_interface_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_output_acl_set_interface
#define defined_vapi_msg_output_acl_set_interface
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 ip4_table_index;
  u32 ip6_table_index;
  u32 l2_table_index;
  bool is_add; 
} vapi_payload_output_acl_set_interface;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_output_acl_set_interface payload;
} vapi_msg_output_acl_set_interface;

static inline void vapi_msg_output_acl_set_interface_payload_hton(vapi_payload_output_acl_set_interface *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->ip4_table_index = htobe32(payload->ip4_table_index);
  payload->ip6_table_index = htobe32(payload->ip6_table_index);
  payload->l2_table_index = htobe32(payload->l2_table_index);
}

static inline void vapi_msg_output_acl_set_interface_payload_ntoh(vapi_payload_output_acl_set_interface *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->ip4_table_index = be32toh(payload->ip4_table_index);
  payload->ip6_table_index = be32toh(payload->ip6_table_index);
  payload->l2_table_index = be32toh(payload->l2_table_index);
}

static inline void vapi_msg_output_acl_set_interface_hton(vapi_msg_output_acl_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_output_acl_set_interface'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_output_acl_set_interface_payload_hton(&msg->payload);
}

static inline void vapi_msg_output_acl_set_interface_ntoh(vapi_msg_output_acl_set_interface *msg)
{
  VAPI_DBG("Swapping `vapi_msg_output_acl_set_interface'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_output_acl_set_interface_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_output_acl_set_interface_msg_size(vapi_msg_output_acl_set_interface *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_output_acl_set_interface_msg_size(vapi_msg_output_acl_set_interface *msg, uword buf_size)
{
  if (sizeof(vapi_msg_output_acl_set_interface) > buf_size)
    {
      VAPI_ERR("Truncated 'output_acl_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_output_acl_set_interface));
      return -1;
    }
  if (vapi_calc_output_acl_set_interface_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'output_acl_set_interface' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_output_acl_set_interface_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_output_acl_set_interface* vapi_alloc_output_acl_set_interface(struct vapi_ctx_s *ctx)
{
  vapi_msg_output_acl_set_interface *msg = NULL;
  const size_t size = sizeof(vapi_msg_output_acl_set_interface);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_output_acl_set_interface*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_output_acl_set_interface);

  return msg;
}

static inline vapi_error_e vapi_output_acl_set_interface(struct vapi_ctx_s *ctx,
  vapi_msg_output_acl_set_interface *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_output_acl_set_interface_reply *reply),
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
  vapi_msg_output_acl_set_interface_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_output_acl_set_interface_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_output_acl_set_interface_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_output_acl_set_interface()
{
  static const char name[] = "output_acl_set_interface";
  static const char name_with_crc[] = "output_acl_set_interface_de7ad708";
  static vapi_message_desc_t __vapi_metadata_output_acl_set_interface = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_output_acl_set_interface, payload),
    (verify_msg_size_fn_t)vapi_verify_output_acl_set_interface_msg_size,
    (generic_swap_fn_t)vapi_msg_output_acl_set_interface_hton,
    (generic_swap_fn_t)vapi_msg_output_acl_set_interface_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_output_acl_set_interface = vapi_register_msg(&__vapi_metadata_output_acl_set_interface);
  VAPI_DBG("Assigned msg id %d to output_acl_set_interface", vapi_msg_id_output_acl_set_interface);
}
#endif

#ifndef defined_vapi_msg_classify_pcap_lookup_table_reply
#define defined_vapi_msg_classify_pcap_lookup_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_index; 
} vapi_payload_classify_pcap_lookup_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_pcap_lookup_table_reply payload;
} vapi_msg_classify_pcap_lookup_table_reply;

static inline void vapi_msg_classify_pcap_lookup_table_reply_payload_hton(vapi_payload_classify_pcap_lookup_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_pcap_lookup_table_reply_payload_ntoh(vapi_payload_classify_pcap_lookup_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_pcap_lookup_table_reply_hton(vapi_msg_classify_pcap_lookup_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_lookup_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_pcap_lookup_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_lookup_table_reply_ntoh(vapi_msg_classify_pcap_lookup_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_lookup_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_lookup_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_lookup_table_reply_msg_size(vapi_msg_classify_pcap_lookup_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_pcap_lookup_table_reply_msg_size(vapi_msg_classify_pcap_lookup_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_lookup_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_lookup_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_lookup_table_reply));
      return -1;
    }
  if (vapi_calc_classify_pcap_lookup_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_lookup_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_lookup_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_pcap_lookup_table_reply()
{
  static const char name[] = "classify_pcap_lookup_table_reply";
  static const char name_with_crc[] = "classify_pcap_lookup_table_reply_9c6c6773";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_lookup_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_pcap_lookup_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_lookup_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_lookup_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_lookup_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_lookup_table_reply = vapi_register_msg(&__vapi_metadata_classify_pcap_lookup_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_pcap_lookup_table_reply", vapi_msg_id_classify_pcap_lookup_table_reply);
}

static inline void vapi_set_vapi_msg_classify_pcap_lookup_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_pcap_lookup_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_pcap_lookup_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_pcap_lookup_table
#define defined_vapi_msg_classify_pcap_lookup_table
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 skip_n_vectors;
  u32 match_n_vectors;
  u32 mask_len;
  u8 mask[0]; 
} vapi_payload_classify_pcap_lookup_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_pcap_lookup_table payload;
} vapi_msg_classify_pcap_lookup_table;

static inline void vapi_msg_classify_pcap_lookup_table_payload_hton(vapi_payload_classify_pcap_lookup_table *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->skip_n_vectors = htobe32(payload->skip_n_vectors);
  payload->match_n_vectors = htobe32(payload->match_n_vectors);
  payload->mask_len = htobe32(payload->mask_len);
}

static inline void vapi_msg_classify_pcap_lookup_table_payload_ntoh(vapi_payload_classify_pcap_lookup_table *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->skip_n_vectors = be32toh(payload->skip_n_vectors);
  payload->match_n_vectors = be32toh(payload->match_n_vectors);
  payload->mask_len = be32toh(payload->mask_len);
}

static inline void vapi_msg_classify_pcap_lookup_table_hton(vapi_msg_classify_pcap_lookup_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_lookup_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_pcap_lookup_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_lookup_table_ntoh(vapi_msg_classify_pcap_lookup_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_lookup_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_lookup_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_lookup_table_msg_size(vapi_msg_classify_pcap_lookup_table *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.mask[0]) * msg->payload.mask_len;
}

static inline int vapi_verify_classify_pcap_lookup_table_msg_size(vapi_msg_classify_pcap_lookup_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_lookup_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_lookup_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_lookup_table));
      return -1;
    }
  if (vapi_calc_classify_pcap_lookup_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_lookup_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_lookup_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_pcap_lookup_table* vapi_alloc_classify_pcap_lookup_table(struct vapi_ctx_s *ctx, size_t _mask_array_size)
{
  vapi_msg_classify_pcap_lookup_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_pcap_lookup_table) + sizeof(msg->payload.mask[0]) * _mask_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_pcap_lookup_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_pcap_lookup_table);
  msg->payload.mask_len = _mask_array_size;

  return msg;
}

static inline vapi_error_e vapi_classify_pcap_lookup_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_pcap_lookup_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_pcap_lookup_table_reply *reply),
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
  vapi_msg_classify_pcap_lookup_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_pcap_lookup_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_pcap_lookup_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_pcap_lookup_table()
{
  static const char name[] = "classify_pcap_lookup_table";
  static const char name_with_crc[] = "classify_pcap_lookup_table_e1b4cc6b";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_lookup_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_pcap_lookup_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_lookup_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_lookup_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_lookup_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_lookup_table = vapi_register_msg(&__vapi_metadata_classify_pcap_lookup_table);
  VAPI_DBG("Assigned msg id %d to classify_pcap_lookup_table", vapi_msg_id_classify_pcap_lookup_table);
}
#endif

#ifndef defined_vapi_msg_classify_pcap_set_table_reply
#define defined_vapi_msg_classify_pcap_set_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_index; 
} vapi_payload_classify_pcap_set_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_pcap_set_table_reply payload;
} vapi_msg_classify_pcap_set_table_reply;

static inline void vapi_msg_classify_pcap_set_table_reply_payload_hton(vapi_payload_classify_pcap_set_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_pcap_set_table_reply_payload_ntoh(vapi_payload_classify_pcap_set_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_pcap_set_table_reply_hton(vapi_msg_classify_pcap_set_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_set_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_pcap_set_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_set_table_reply_ntoh(vapi_msg_classify_pcap_set_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_set_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_set_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_set_table_reply_msg_size(vapi_msg_classify_pcap_set_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_pcap_set_table_reply_msg_size(vapi_msg_classify_pcap_set_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_set_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_set_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_set_table_reply));
      return -1;
    }
  if (vapi_calc_classify_pcap_set_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_set_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_set_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_pcap_set_table_reply()
{
  static const char name[] = "classify_pcap_set_table_reply";
  static const char name_with_crc[] = "classify_pcap_set_table_reply_9c6c6773";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_set_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_pcap_set_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_set_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_set_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_set_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_set_table_reply = vapi_register_msg(&__vapi_metadata_classify_pcap_set_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_pcap_set_table_reply", vapi_msg_id_classify_pcap_set_table_reply);
}

static inline void vapi_set_vapi_msg_classify_pcap_set_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_pcap_set_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_pcap_set_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_pcap_set_table
#define defined_vapi_msg_classify_pcap_set_table
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  u32 table_index;
  bool sort_masks; 
} vapi_payload_classify_pcap_set_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_pcap_set_table payload;
} vapi_msg_classify_pcap_set_table;

static inline void vapi_msg_classify_pcap_set_table_payload_hton(vapi_payload_classify_pcap_set_table *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_pcap_set_table_payload_ntoh(vapi_payload_classify_pcap_set_table *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_pcap_set_table_hton(vapi_msg_classify_pcap_set_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_set_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_pcap_set_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_set_table_ntoh(vapi_msg_classify_pcap_set_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_set_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_set_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_set_table_msg_size(vapi_msg_classify_pcap_set_table *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_pcap_set_table_msg_size(vapi_msg_classify_pcap_set_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_set_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_set_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_set_table));
      return -1;
    }
  if (vapi_calc_classify_pcap_set_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_set_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_set_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_pcap_set_table* vapi_alloc_classify_pcap_set_table(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_pcap_set_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_pcap_set_table);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_pcap_set_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_pcap_set_table);

  return msg;
}

static inline vapi_error_e vapi_classify_pcap_set_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_pcap_set_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_pcap_set_table_reply *reply),
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
  vapi_msg_classify_pcap_set_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_pcap_set_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_pcap_set_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_pcap_set_table()
{
  static const char name[] = "classify_pcap_set_table";
  static const char name_with_crc[] = "classify_pcap_set_table_006051b3";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_set_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_pcap_set_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_set_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_set_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_set_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_set_table = vapi_register_msg(&__vapi_metadata_classify_pcap_set_table);
  VAPI_DBG("Assigned msg id %d to classify_pcap_set_table", vapi_msg_id_classify_pcap_set_table);
}
#endif

#ifndef defined_vapi_msg_classify_pcap_get_tables_reply
#define defined_vapi_msg_classify_pcap_get_tables_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  u32 indices[0]; 
} vapi_payload_classify_pcap_get_tables_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_pcap_get_tables_reply payload;
} vapi_msg_classify_pcap_get_tables_reply;

static inline void vapi_msg_classify_pcap_get_tables_reply_payload_hton(vapi_payload_classify_pcap_get_tables_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->indices[i] = htobe32(payload->indices[i]); } } while(0);
}

static inline void vapi_msg_classify_pcap_get_tables_reply_payload_ntoh(vapi_payload_classify_pcap_get_tables_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->indices[i] = be32toh(payload->indices[i]); } } while(0);
}

static inline void vapi_msg_classify_pcap_get_tables_reply_hton(vapi_msg_classify_pcap_get_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_get_tables_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_pcap_get_tables_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_get_tables_reply_ntoh(vapi_msg_classify_pcap_get_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_get_tables_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_get_tables_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_get_tables_reply_msg_size(vapi_msg_classify_pcap_get_tables_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.indices[0]) * msg->payload.count;
}

static inline int vapi_verify_classify_pcap_get_tables_reply_msg_size(vapi_msg_classify_pcap_get_tables_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_get_tables_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_get_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_get_tables_reply));
      return -1;
    }
  if (vapi_calc_classify_pcap_get_tables_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_get_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_get_tables_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_pcap_get_tables_reply()
{
  static const char name[] = "classify_pcap_get_tables_reply";
  static const char name_with_crc[] = "classify_pcap_get_tables_reply_5f5bc9e6";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_get_tables_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_pcap_get_tables_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_get_tables_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_get_tables_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_get_tables_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_get_tables_reply = vapi_register_msg(&__vapi_metadata_classify_pcap_get_tables_reply);
  VAPI_DBG("Assigned msg id %d to classify_pcap_get_tables_reply", vapi_msg_id_classify_pcap_get_tables_reply);
}

static inline void vapi_set_vapi_msg_classify_pcap_get_tables_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_pcap_get_tables_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_pcap_get_tables_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_pcap_get_tables
#define defined_vapi_msg_classify_pcap_get_tables
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_classify_pcap_get_tables;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_pcap_get_tables payload;
} vapi_msg_classify_pcap_get_tables;

static inline void vapi_msg_classify_pcap_get_tables_payload_hton(vapi_payload_classify_pcap_get_tables *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_classify_pcap_get_tables_payload_ntoh(vapi_payload_classify_pcap_get_tables *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_classify_pcap_get_tables_hton(vapi_msg_classify_pcap_get_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_get_tables'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_pcap_get_tables_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_pcap_get_tables_ntoh(vapi_msg_classify_pcap_get_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_pcap_get_tables'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_pcap_get_tables_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_pcap_get_tables_msg_size(vapi_msg_classify_pcap_get_tables *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_pcap_get_tables_msg_size(vapi_msg_classify_pcap_get_tables *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_pcap_get_tables) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_get_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_pcap_get_tables));
      return -1;
    }
  if (vapi_calc_classify_pcap_get_tables_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_pcap_get_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_pcap_get_tables_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_pcap_get_tables* vapi_alloc_classify_pcap_get_tables(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_pcap_get_tables *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_pcap_get_tables);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_pcap_get_tables*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_pcap_get_tables);

  return msg;
}

static inline vapi_error_e vapi_classify_pcap_get_tables(struct vapi_ctx_s *ctx,
  vapi_msg_classify_pcap_get_tables *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_pcap_get_tables_reply *reply),
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
  vapi_msg_classify_pcap_get_tables_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_pcap_get_tables_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_pcap_get_tables_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_pcap_get_tables()
{
  static const char name[] = "classify_pcap_get_tables";
  static const char name_with_crc[] = "classify_pcap_get_tables_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_classify_pcap_get_tables = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_pcap_get_tables, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_pcap_get_tables_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_pcap_get_tables_hton,
    (generic_swap_fn_t)vapi_msg_classify_pcap_get_tables_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_pcap_get_tables = vapi_register_msg(&__vapi_metadata_classify_pcap_get_tables);
  VAPI_DBG("Assigned msg id %d to classify_pcap_get_tables", vapi_msg_id_classify_pcap_get_tables);
}
#endif

#ifndef defined_vapi_msg_classify_trace_lookup_table_reply
#define defined_vapi_msg_classify_trace_lookup_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_index; 
} vapi_payload_classify_trace_lookup_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_trace_lookup_table_reply payload;
} vapi_msg_classify_trace_lookup_table_reply;

static inline void vapi_msg_classify_trace_lookup_table_reply_payload_hton(vapi_payload_classify_trace_lookup_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_trace_lookup_table_reply_payload_ntoh(vapi_payload_classify_trace_lookup_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_trace_lookup_table_reply_hton(vapi_msg_classify_trace_lookup_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_lookup_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_trace_lookup_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_trace_lookup_table_reply_ntoh(vapi_msg_classify_trace_lookup_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_lookup_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_trace_lookup_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_trace_lookup_table_reply_msg_size(vapi_msg_classify_trace_lookup_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_trace_lookup_table_reply_msg_size(vapi_msg_classify_trace_lookup_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_lookup_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_lookup_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_lookup_table_reply));
      return -1;
    }
  if (vapi_calc_classify_trace_lookup_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_lookup_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_lookup_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_trace_lookup_table_reply()
{
  static const char name[] = "classify_trace_lookup_table_reply";
  static const char name_with_crc[] = "classify_trace_lookup_table_reply_9c6c6773";
  static vapi_message_desc_t __vapi_metadata_classify_trace_lookup_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_trace_lookup_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_trace_lookup_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_lookup_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_lookup_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_lookup_table_reply = vapi_register_msg(&__vapi_metadata_classify_trace_lookup_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_trace_lookup_table_reply", vapi_msg_id_classify_trace_lookup_table_reply);
}

static inline void vapi_set_vapi_msg_classify_trace_lookup_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_trace_lookup_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_trace_lookup_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_trace_lookup_table
#define defined_vapi_msg_classify_trace_lookup_table
typedef struct __attribute__ ((__packed__)) {
  u32 skip_n_vectors;
  u32 match_n_vectors;
  u32 mask_len;
  u8 mask[0]; 
} vapi_payload_classify_trace_lookup_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_trace_lookup_table payload;
} vapi_msg_classify_trace_lookup_table;

static inline void vapi_msg_classify_trace_lookup_table_payload_hton(vapi_payload_classify_trace_lookup_table *payload)
{
  payload->skip_n_vectors = htobe32(payload->skip_n_vectors);
  payload->match_n_vectors = htobe32(payload->match_n_vectors);
  payload->mask_len = htobe32(payload->mask_len);
}

static inline void vapi_msg_classify_trace_lookup_table_payload_ntoh(vapi_payload_classify_trace_lookup_table *payload)
{
  payload->skip_n_vectors = be32toh(payload->skip_n_vectors);
  payload->match_n_vectors = be32toh(payload->match_n_vectors);
  payload->mask_len = be32toh(payload->mask_len);
}

static inline void vapi_msg_classify_trace_lookup_table_hton(vapi_msg_classify_trace_lookup_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_lookup_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_trace_lookup_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_trace_lookup_table_ntoh(vapi_msg_classify_trace_lookup_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_lookup_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_trace_lookup_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_trace_lookup_table_msg_size(vapi_msg_classify_trace_lookup_table *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.mask[0]) * msg->payload.mask_len;
}

static inline int vapi_verify_classify_trace_lookup_table_msg_size(vapi_msg_classify_trace_lookup_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_lookup_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_lookup_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_lookup_table));
      return -1;
    }
  if (vapi_calc_classify_trace_lookup_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_lookup_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_lookup_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_trace_lookup_table* vapi_alloc_classify_trace_lookup_table(struct vapi_ctx_s *ctx, size_t _mask_array_size)
{
  vapi_msg_classify_trace_lookup_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_trace_lookup_table) + sizeof(msg->payload.mask[0]) * _mask_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_trace_lookup_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_trace_lookup_table);
  msg->payload.mask_len = _mask_array_size;

  return msg;
}

static inline vapi_error_e vapi_classify_trace_lookup_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_trace_lookup_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_trace_lookup_table_reply *reply),
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
  vapi_msg_classify_trace_lookup_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_trace_lookup_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_trace_lookup_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_trace_lookup_table()
{
  static const char name[] = "classify_trace_lookup_table";
  static const char name_with_crc[] = "classify_trace_lookup_table_3f7b72e4";
  static vapi_message_desc_t __vapi_metadata_classify_trace_lookup_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_trace_lookup_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_trace_lookup_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_lookup_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_lookup_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_lookup_table = vapi_register_msg(&__vapi_metadata_classify_trace_lookup_table);
  VAPI_DBG("Assigned msg id %d to classify_trace_lookup_table", vapi_msg_id_classify_trace_lookup_table);
}
#endif

#ifndef defined_vapi_msg_classify_trace_set_table_reply
#define defined_vapi_msg_classify_trace_set_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 table_index; 
} vapi_payload_classify_trace_set_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_trace_set_table_reply payload;
} vapi_msg_classify_trace_set_table_reply;

static inline void vapi_msg_classify_trace_set_table_reply_payload_hton(vapi_payload_classify_trace_set_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_trace_set_table_reply_payload_ntoh(vapi_payload_classify_trace_set_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_trace_set_table_reply_hton(vapi_msg_classify_trace_set_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_set_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_trace_set_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_trace_set_table_reply_ntoh(vapi_msg_classify_trace_set_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_set_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_trace_set_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_trace_set_table_reply_msg_size(vapi_msg_classify_trace_set_table_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_trace_set_table_reply_msg_size(vapi_msg_classify_trace_set_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_set_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_set_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_set_table_reply));
      return -1;
    }
  if (vapi_calc_classify_trace_set_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_set_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_set_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_trace_set_table_reply()
{
  static const char name[] = "classify_trace_set_table_reply";
  static const char name_with_crc[] = "classify_trace_set_table_reply_9c6c6773";
  static vapi_message_desc_t __vapi_metadata_classify_trace_set_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_trace_set_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_trace_set_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_set_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_set_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_set_table_reply = vapi_register_msg(&__vapi_metadata_classify_trace_set_table_reply);
  VAPI_DBG("Assigned msg id %d to classify_trace_set_table_reply", vapi_msg_id_classify_trace_set_table_reply);
}

static inline void vapi_set_vapi_msg_classify_trace_set_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_trace_set_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_trace_set_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_trace_set_table
#define defined_vapi_msg_classify_trace_set_table
typedef struct __attribute__ ((__packed__)) {
  u32 table_index;
  bool sort_masks; 
} vapi_payload_classify_trace_set_table;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_classify_trace_set_table payload;
} vapi_msg_classify_trace_set_table;

static inline void vapi_msg_classify_trace_set_table_payload_hton(vapi_payload_classify_trace_set_table *payload)
{
  payload->table_index = htobe32(payload->table_index);
}

static inline void vapi_msg_classify_trace_set_table_payload_ntoh(vapi_payload_classify_trace_set_table *payload)
{
  payload->table_index = be32toh(payload->table_index);
}

static inline void vapi_msg_classify_trace_set_table_hton(vapi_msg_classify_trace_set_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_set_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_classify_trace_set_table_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_trace_set_table_ntoh(vapi_msg_classify_trace_set_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_set_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_classify_trace_set_table_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_trace_set_table_msg_size(vapi_msg_classify_trace_set_table *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_trace_set_table_msg_size(vapi_msg_classify_trace_set_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_set_table) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_set_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_set_table));
      return -1;
    }
  if (vapi_calc_classify_trace_set_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_set_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_set_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_trace_set_table* vapi_alloc_classify_trace_set_table(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_trace_set_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_trace_set_table);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_trace_set_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_trace_set_table);

  return msg;
}

static inline vapi_error_e vapi_classify_trace_set_table(struct vapi_ctx_s *ctx,
  vapi_msg_classify_trace_set_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_trace_set_table_reply *reply),
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
  vapi_msg_classify_trace_set_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_trace_set_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_trace_set_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_trace_set_table()
{
  static const char name[] = "classify_trace_set_table";
  static const char name_with_crc[] = "classify_trace_set_table_3909b55a";
  static vapi_message_desc_t __vapi_metadata_classify_trace_set_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_classify_trace_set_table, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_trace_set_table_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_set_table_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_set_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_set_table = vapi_register_msg(&__vapi_metadata_classify_trace_set_table);
  VAPI_DBG("Assigned msg id %d to classify_trace_set_table", vapi_msg_id_classify_trace_set_table);
}
#endif

#ifndef defined_vapi_msg_classify_trace_get_tables_reply
#define defined_vapi_msg_classify_trace_get_tables_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  u32 indices[0]; 
} vapi_payload_classify_trace_get_tables_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_classify_trace_get_tables_reply payload;
} vapi_msg_classify_trace_get_tables_reply;

static inline void vapi_msg_classify_trace_get_tables_reply_payload_hton(vapi_payload_classify_trace_get_tables_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { payload->indices[i] = htobe32(payload->indices[i]); } } while(0);
}

static inline void vapi_msg_classify_trace_get_tables_reply_payload_ntoh(vapi_payload_classify_trace_get_tables_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { payload->indices[i] = be32toh(payload->indices[i]); } } while(0);
}

static inline void vapi_msg_classify_trace_get_tables_reply_hton(vapi_msg_classify_trace_get_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_get_tables_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_classify_trace_get_tables_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_classify_trace_get_tables_reply_ntoh(vapi_msg_classify_trace_get_tables_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_get_tables_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_classify_trace_get_tables_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_classify_trace_get_tables_reply_msg_size(vapi_msg_classify_trace_get_tables_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.indices[0]) * msg->payload.count;
}

static inline int vapi_verify_classify_trace_get_tables_reply_msg_size(vapi_msg_classify_trace_get_tables_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_get_tables_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_get_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_get_tables_reply));
      return -1;
    }
  if (vapi_calc_classify_trace_get_tables_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_get_tables_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_get_tables_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_classify_trace_get_tables_reply()
{
  static const char name[] = "classify_trace_get_tables_reply";
  static const char name_with_crc[] = "classify_trace_get_tables_reply_5f5bc9e6";
  static vapi_message_desc_t __vapi_metadata_classify_trace_get_tables_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_classify_trace_get_tables_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_classify_trace_get_tables_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_get_tables_reply_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_get_tables_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_get_tables_reply = vapi_register_msg(&__vapi_metadata_classify_trace_get_tables_reply);
  VAPI_DBG("Assigned msg id %d to classify_trace_get_tables_reply", vapi_msg_id_classify_trace_get_tables_reply);
}

static inline void vapi_set_vapi_msg_classify_trace_get_tables_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_classify_trace_get_tables_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_classify_trace_get_tables_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_classify_trace_get_tables
#define defined_vapi_msg_classify_trace_get_tables
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_classify_trace_get_tables;

static inline void vapi_msg_classify_trace_get_tables_hton(vapi_msg_classify_trace_get_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_get_tables'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_classify_trace_get_tables_ntoh(vapi_msg_classify_trace_get_tables *msg)
{
  VAPI_DBG("Swapping `vapi_msg_classify_trace_get_tables'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_classify_trace_get_tables_msg_size(vapi_msg_classify_trace_get_tables *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_classify_trace_get_tables_msg_size(vapi_msg_classify_trace_get_tables *msg, uword buf_size)
{
  if (sizeof(vapi_msg_classify_trace_get_tables) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_get_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_classify_trace_get_tables));
      return -1;
    }
  if (vapi_calc_classify_trace_get_tables_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'classify_trace_get_tables' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_classify_trace_get_tables_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_classify_trace_get_tables* vapi_alloc_classify_trace_get_tables(struct vapi_ctx_s *ctx)
{
  vapi_msg_classify_trace_get_tables *msg = NULL;
  const size_t size = sizeof(vapi_msg_classify_trace_get_tables);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_classify_trace_get_tables*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_classify_trace_get_tables);

  return msg;
}

static inline vapi_error_e vapi_classify_trace_get_tables(struct vapi_ctx_s *ctx,
  vapi_msg_classify_trace_get_tables *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_classify_trace_get_tables_reply *reply),
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
  vapi_msg_classify_trace_get_tables_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_classify_trace_get_tables_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_classify_trace_get_tables_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_classify_trace_get_tables()
{
  static const char name[] = "classify_trace_get_tables";
  static const char name_with_crc[] = "classify_trace_get_tables_51077d14";
  static vapi_message_desc_t __vapi_metadata_classify_trace_get_tables = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_classify_trace_get_tables_msg_size,
    (generic_swap_fn_t)vapi_msg_classify_trace_get_tables_hton,
    (generic_swap_fn_t)vapi_msg_classify_trace_get_tables_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_classify_trace_get_tables = vapi_register_msg(&__vapi_metadata_classify_trace_get_tables);
  VAPI_DBG("Assigned msg id %d to classify_trace_get_tables", vapi_msg_id_classify_trace_get_tables);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
