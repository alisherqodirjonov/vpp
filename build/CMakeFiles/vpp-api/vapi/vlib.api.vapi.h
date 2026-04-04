#ifndef __included_vlib_api_json
#define __included_vlib_api_json

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
#include <vapi/memclnt.api.vapi.h>

extern vapi_msg_id_t vapi_msg_id_cli;
extern vapi_msg_id_t vapi_msg_id_cli_inband;
extern vapi_msg_id_t vapi_msg_id_cli_reply;
extern vapi_msg_id_t vapi_msg_id_cli_inband_reply;
extern vapi_msg_id_t vapi_msg_id_get_node_index;
extern vapi_msg_id_t vapi_msg_id_get_node_index_reply;
extern vapi_msg_id_t vapi_msg_id_add_node_next;
extern vapi_msg_id_t vapi_msg_id_add_node_next_reply;
extern vapi_msg_id_t vapi_msg_id_show_threads;
extern vapi_msg_id_t vapi_msg_id_show_threads_reply;
extern vapi_msg_id_t vapi_msg_id_get_node_graph;
extern vapi_msg_id_t vapi_msg_id_get_node_graph_reply;
extern vapi_msg_id_t vapi_msg_id_get_next_index;
extern vapi_msg_id_t vapi_msg_id_get_next_index_reply;
extern vapi_msg_id_t vapi_msg_id_get_f64_endian_value;
extern vapi_msg_id_t vapi_msg_id_get_f64_endian_value_reply;
extern vapi_msg_id_t vapi_msg_id_get_f64_increment_by_one;
extern vapi_msg_id_t vapi_msg_id_get_f64_increment_by_one_reply;

#define DEFINE_VAPI_MSG_IDS_VLIB_API_JSON\
  vapi_msg_id_t vapi_msg_id_cli;\
  vapi_msg_id_t vapi_msg_id_cli_inband;\
  vapi_msg_id_t vapi_msg_id_cli_reply;\
  vapi_msg_id_t vapi_msg_id_cli_inband_reply;\
  vapi_msg_id_t vapi_msg_id_get_node_index;\
  vapi_msg_id_t vapi_msg_id_get_node_index_reply;\
  vapi_msg_id_t vapi_msg_id_add_node_next;\
  vapi_msg_id_t vapi_msg_id_add_node_next_reply;\
  vapi_msg_id_t vapi_msg_id_show_threads;\
  vapi_msg_id_t vapi_msg_id_show_threads_reply;\
  vapi_msg_id_t vapi_msg_id_get_node_graph;\
  vapi_msg_id_t vapi_msg_id_get_node_graph_reply;\
  vapi_msg_id_t vapi_msg_id_get_next_index;\
  vapi_msg_id_t vapi_msg_id_get_next_index_reply;\
  vapi_msg_id_t vapi_msg_id_get_f64_endian_value;\
  vapi_msg_id_t vapi_msg_id_get_f64_endian_value_reply;\
  vapi_msg_id_t vapi_msg_id_get_f64_increment_by_one;\
  vapi_msg_id_t vapi_msg_id_get_f64_increment_by_one_reply;


#ifndef defined_vapi_type_thread_data
#define defined_vapi_type_thread_data
typedef struct __attribute__((__packed__)) {
  u32 id;
  u8 name[64];
  u8 type[64];
  u32 pid;
  u32 cpu_id;
  u32 core;
  u32 cpu_socket;
} vapi_type_thread_data;

static inline void vapi_type_thread_data_hton(vapi_type_thread_data *msg)
{
  msg->id = htobe32(msg->id);
  msg->pid = htobe32(msg->pid);
  msg->cpu_id = htobe32(msg->cpu_id);
  msg->core = htobe32(msg->core);
  msg->cpu_socket = htobe32(msg->cpu_socket);
}

static inline void vapi_type_thread_data_ntoh(vapi_type_thread_data *msg)
{
  msg->id = be32toh(msg->id);
  msg->pid = be32toh(msg->pid);
  msg->cpu_id = be32toh(msg->cpu_id);
  msg->core = be32toh(msg->core);
  msg->cpu_socket = be32toh(msg->cpu_socket);
}
#endif

#ifndef defined_vapi_msg_cli_reply
#define defined_vapi_msg_cli_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u64 reply_in_shmem; 
} vapi_payload_cli_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cli_reply payload;
} vapi_msg_cli_reply;

static inline void vapi_msg_cli_reply_payload_hton(vapi_payload_cli_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->reply_in_shmem = htobe64(payload->reply_in_shmem);
}

static inline void vapi_msg_cli_reply_payload_ntoh(vapi_payload_cli_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->reply_in_shmem = be64toh(payload->reply_in_shmem);
}

static inline void vapi_msg_cli_reply_hton(vapi_msg_cli_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cli_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cli_reply_ntoh(vapi_msg_cli_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cli_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cli_reply_msg_size(vapi_msg_cli_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cli_reply_msg_size(vapi_msg_cli_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cli_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cli_reply));
      return -1;
    }
  if (vapi_calc_cli_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cli_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cli_reply()
{
  static const char name[] = "cli_reply";
  static const char name_with_crc[] = "cli_reply_06d68297";
  static vapi_message_desc_t __vapi_metadata_cli_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cli_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cli_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cli_reply_hton,
    (generic_swap_fn_t)vapi_msg_cli_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cli_reply = vapi_register_msg(&__vapi_metadata_cli_reply);
  VAPI_DBG("Assigned msg id %d to cli_reply", vapi_msg_id_cli_reply);
}

static inline void vapi_set_vapi_msg_cli_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cli_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cli_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cli
#define defined_vapi_msg_cli
typedef struct __attribute__ ((__packed__)) {
  u64 cmd_in_shmem; 
} vapi_payload_cli;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cli payload;
} vapi_msg_cli;

static inline void vapi_msg_cli_payload_hton(vapi_payload_cli *payload)
{
  payload->cmd_in_shmem = htobe64(payload->cmd_in_shmem);
}

static inline void vapi_msg_cli_payload_ntoh(vapi_payload_cli *payload)
{
  payload->cmd_in_shmem = be64toh(payload->cmd_in_shmem);
}

static inline void vapi_msg_cli_hton(vapi_msg_cli *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cli_payload_hton(&msg->payload);
}

static inline void vapi_msg_cli_ntoh(vapi_msg_cli *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cli_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cli_msg_size(vapi_msg_cli *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_cli_msg_size(vapi_msg_cli *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cli) > buf_size)
    {
      VAPI_ERR("Truncated 'cli' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cli));
      return -1;
    }
  if (vapi_calc_cli_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cli' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cli_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cli* vapi_alloc_cli(struct vapi_ctx_s *ctx)
{
  vapi_msg_cli *msg = NULL;
  const size_t size = sizeof(vapi_msg_cli);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cli*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cli);

  return msg;
}

static inline vapi_error_e vapi_cli(struct vapi_ctx_s *ctx,
  vapi_msg_cli *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cli_reply *reply),
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
  vapi_msg_cli_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cli_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cli_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cli()
{
  static const char name[] = "cli";
  static const char name_with_crc[] = "cli_23bfbfff";
  static vapi_message_desc_t __vapi_metadata_cli = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cli, payload),
    (verify_msg_size_fn_t)vapi_verify_cli_msg_size,
    (generic_swap_fn_t)vapi_msg_cli_hton,
    (generic_swap_fn_t)vapi_msg_cli_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cli = vapi_register_msg(&__vapi_metadata_cli);
  VAPI_DBG("Assigned msg id %d to cli", vapi_msg_id_cli);
}
#endif

#ifndef defined_vapi_msg_cli_inband_reply
#define defined_vapi_msg_cli_inband_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vl_api_string_t reply; 
} vapi_payload_cli_inband_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_cli_inband_reply payload;
} vapi_msg_cli_inband_reply;

static inline void vapi_msg_cli_inband_reply_payload_hton(vapi_payload_cli_inband_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->reply);
}

static inline void vapi_msg_cli_inband_reply_payload_ntoh(vapi_payload_cli_inband_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->reply);
}

static inline void vapi_msg_cli_inband_reply_hton(vapi_msg_cli_inband_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_inband_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_cli_inband_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_cli_inband_reply_ntoh(vapi_msg_cli_inband_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_inband_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_cli_inband_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cli_inband_reply_msg_size(vapi_msg_cli_inband_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.reply.buf[0]) * msg->payload.reply.length;
}

static inline int vapi_verify_cli_inband_reply_msg_size(vapi_msg_cli_inband_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cli_inband_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_inband_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cli_inband_reply));
      return -1;
    }
  if (vapi_calc_cli_inband_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_inband_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cli_inband_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_cli_inband_reply()
{
  static const char name[] = "cli_inband_reply";
  static const char name_with_crc[] = "cli_inband_reply_05879051";
  static vapi_message_desc_t __vapi_metadata_cli_inband_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_cli_inband_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_cli_inband_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_cli_inband_reply_hton,
    (generic_swap_fn_t)vapi_msg_cli_inband_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cli_inband_reply = vapi_register_msg(&__vapi_metadata_cli_inband_reply);
  VAPI_DBG("Assigned msg id %d to cli_inband_reply", vapi_msg_id_cli_inband_reply);
}

static inline void vapi_set_vapi_msg_cli_inband_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_cli_inband_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_cli_inband_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_cli_inband
#define defined_vapi_msg_cli_inband
typedef struct __attribute__ ((__packed__)) {
  vl_api_string_t cmd; 
} vapi_payload_cli_inband;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_cli_inband payload;
} vapi_msg_cli_inband;

static inline void vapi_msg_cli_inband_payload_hton(vapi_payload_cli_inband *payload)
{
  vl_api_string_t_hton(&payload->cmd);
}

static inline void vapi_msg_cli_inband_payload_ntoh(vapi_payload_cli_inband *payload)
{
  vl_api_string_t_ntoh(&payload->cmd);
}

static inline void vapi_msg_cli_inband_hton(vapi_msg_cli_inband *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_inband'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_cli_inband_payload_hton(&msg->payload);
}

static inline void vapi_msg_cli_inband_ntoh(vapi_msg_cli_inband *msg)
{
  VAPI_DBG("Swapping `vapi_msg_cli_inband'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_cli_inband_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_cli_inband_msg_size(vapi_msg_cli_inband *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.cmd.buf[0]) * msg->payload.cmd.length;
}

static inline int vapi_verify_cli_inband_msg_size(vapi_msg_cli_inband *msg, uword buf_size)
{
  if (sizeof(vapi_msg_cli_inband) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_inband' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_cli_inband));
      return -1;
    }
  if (vapi_calc_cli_inband_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'cli_inband' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_cli_inband_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_cli_inband* vapi_alloc_cli_inband(struct vapi_ctx_s *ctx, size_t cmd_buf_array_size)
{
  vapi_msg_cli_inband *msg = NULL;
  const size_t size = sizeof(vapi_msg_cli_inband) + sizeof(msg->payload.cmd.buf[0]) * cmd_buf_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_cli_inband*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_cli_inband);
  msg->payload.cmd.length = cmd_buf_array_size;

  return msg;
}

static inline vapi_error_e vapi_cli_inband(struct vapi_ctx_s *ctx,
  vapi_msg_cli_inband *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_cli_inband_reply *reply),
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
  vapi_msg_cli_inband_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_cli_inband_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_cli_inband_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_cli_inband()
{
  static const char name[] = "cli_inband";
  static const char name_with_crc[] = "cli_inband_f8377302";
  static vapi_message_desc_t __vapi_metadata_cli_inband = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_cli_inband, payload),
    (verify_msg_size_fn_t)vapi_verify_cli_inband_msg_size,
    (generic_swap_fn_t)vapi_msg_cli_inband_hton,
    (generic_swap_fn_t)vapi_msg_cli_inband_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_cli_inband = vapi_register_msg(&__vapi_metadata_cli_inband);
  VAPI_DBG("Assigned msg id %d to cli_inband", vapi_msg_id_cli_inband);
}
#endif

#ifndef defined_vapi_msg_get_node_index_reply
#define defined_vapi_msg_get_node_index_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 node_index; 
} vapi_payload_get_node_index_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_node_index_reply payload;
} vapi_msg_get_node_index_reply;

static inline void vapi_msg_get_node_index_reply_payload_hton(vapi_payload_get_node_index_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->node_index = htobe32(payload->node_index);
}

static inline void vapi_msg_get_node_index_reply_payload_ntoh(vapi_payload_get_node_index_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->node_index = be32toh(payload->node_index);
}

static inline void vapi_msg_get_node_index_reply_hton(vapi_msg_get_node_index_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_index_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_node_index_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_node_index_reply_ntoh(vapi_msg_get_node_index_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_index_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_node_index_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_node_index_reply_msg_size(vapi_msg_get_node_index_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_node_index_reply_msg_size(vapi_msg_get_node_index_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_node_index_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_index_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_node_index_reply));
      return -1;
    }
  if (vapi_calc_get_node_index_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_index_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_node_index_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_node_index_reply()
{
  static const char name[] = "get_node_index_reply";
  static const char name_with_crc[] = "get_node_index_reply_a8600b89";
  static vapi_message_desc_t __vapi_metadata_get_node_index_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_node_index_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_node_index_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_node_index_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_node_index_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_node_index_reply = vapi_register_msg(&__vapi_metadata_get_node_index_reply);
  VAPI_DBG("Assigned msg id %d to get_node_index_reply", vapi_msg_id_get_node_index_reply);
}

static inline void vapi_set_vapi_msg_get_node_index_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_node_index_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_node_index_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_node_index
#define defined_vapi_msg_get_node_index
typedef struct __attribute__ ((__packed__)) {
  u8 node_name[64]; 
} vapi_payload_get_node_index;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_get_node_index payload;
} vapi_msg_get_node_index;

static inline void vapi_msg_get_node_index_payload_hton(vapi_payload_get_node_index *payload)
{

}

static inline void vapi_msg_get_node_index_payload_ntoh(vapi_payload_get_node_index *payload)
{

}

static inline void vapi_msg_get_node_index_hton(vapi_msg_get_node_index *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_index'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_get_node_index_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_node_index_ntoh(vapi_msg_get_node_index *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_index'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_get_node_index_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_node_index_msg_size(vapi_msg_get_node_index *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_node_index_msg_size(vapi_msg_get_node_index *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_node_index) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_index' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_node_index));
      return -1;
    }
  if (vapi_calc_get_node_index_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_index' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_node_index_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_node_index* vapi_alloc_get_node_index(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_node_index *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_node_index);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_node_index*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_node_index);

  return msg;
}

static inline vapi_error_e vapi_get_node_index(struct vapi_ctx_s *ctx,
  vapi_msg_get_node_index *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_node_index_reply *reply),
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
  vapi_msg_get_node_index_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_node_index_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_node_index_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_node_index()
{
  static const char name[] = "get_node_index";
  static const char name_with_crc[] = "get_node_index_f1984c64";
  static vapi_message_desc_t __vapi_metadata_get_node_index = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_get_node_index, payload),
    (verify_msg_size_fn_t)vapi_verify_get_node_index_msg_size,
    (generic_swap_fn_t)vapi_msg_get_node_index_hton,
    (generic_swap_fn_t)vapi_msg_get_node_index_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_node_index = vapi_register_msg(&__vapi_metadata_get_node_index);
  VAPI_DBG("Assigned msg id %d to get_node_index", vapi_msg_id_get_node_index);
}
#endif

#ifndef defined_vapi_msg_add_node_next_reply
#define defined_vapi_msg_add_node_next_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 next_index; 
} vapi_payload_add_node_next_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_add_node_next_reply payload;
} vapi_msg_add_node_next_reply;

static inline void vapi_msg_add_node_next_reply_payload_hton(vapi_payload_add_node_next_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->next_index = htobe32(payload->next_index);
}

static inline void vapi_msg_add_node_next_reply_payload_ntoh(vapi_payload_add_node_next_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->next_index = be32toh(payload->next_index);
}

static inline void vapi_msg_add_node_next_reply_hton(vapi_msg_add_node_next_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_node_next_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_add_node_next_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_add_node_next_reply_ntoh(vapi_msg_add_node_next_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_node_next_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_add_node_next_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_add_node_next_reply_msg_size(vapi_msg_add_node_next_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_add_node_next_reply_msg_size(vapi_msg_add_node_next_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_add_node_next_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'add_node_next_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_add_node_next_reply));
      return -1;
    }
  if (vapi_calc_add_node_next_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'add_node_next_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_add_node_next_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_add_node_next_reply()
{
  static const char name[] = "add_node_next_reply";
  static const char name_with_crc[] = "add_node_next_reply_2ed75f32";
  static vapi_message_desc_t __vapi_metadata_add_node_next_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_add_node_next_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_add_node_next_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_add_node_next_reply_hton,
    (generic_swap_fn_t)vapi_msg_add_node_next_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_add_node_next_reply = vapi_register_msg(&__vapi_metadata_add_node_next_reply);
  VAPI_DBG("Assigned msg id %d to add_node_next_reply", vapi_msg_id_add_node_next_reply);
}

static inline void vapi_set_vapi_msg_add_node_next_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_add_node_next_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_add_node_next_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_add_node_next
#define defined_vapi_msg_add_node_next
typedef struct __attribute__ ((__packed__)) {
  u8 node_name[64];
  u8 next_name[64]; 
} vapi_payload_add_node_next;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_add_node_next payload;
} vapi_msg_add_node_next;

static inline void vapi_msg_add_node_next_payload_hton(vapi_payload_add_node_next *payload)
{

}

static inline void vapi_msg_add_node_next_payload_ntoh(vapi_payload_add_node_next *payload)
{

}

static inline void vapi_msg_add_node_next_hton(vapi_msg_add_node_next *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_node_next'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_add_node_next_payload_hton(&msg->payload);
}

static inline void vapi_msg_add_node_next_ntoh(vapi_msg_add_node_next *msg)
{
  VAPI_DBG("Swapping `vapi_msg_add_node_next'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_add_node_next_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_add_node_next_msg_size(vapi_msg_add_node_next *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_add_node_next_msg_size(vapi_msg_add_node_next *msg, uword buf_size)
{
  if (sizeof(vapi_msg_add_node_next) > buf_size)
    {
      VAPI_ERR("Truncated 'add_node_next' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_add_node_next));
      return -1;
    }
  if (vapi_calc_add_node_next_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'add_node_next' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_add_node_next_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_add_node_next* vapi_alloc_add_node_next(struct vapi_ctx_s *ctx)
{
  vapi_msg_add_node_next *msg = NULL;
  const size_t size = sizeof(vapi_msg_add_node_next);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_add_node_next*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_add_node_next);

  return msg;
}

static inline vapi_error_e vapi_add_node_next(struct vapi_ctx_s *ctx,
  vapi_msg_add_node_next *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_add_node_next_reply *reply),
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
  vapi_msg_add_node_next_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_add_node_next_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_add_node_next_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_add_node_next()
{
  static const char name[] = "add_node_next";
  static const char name_with_crc[] = "add_node_next_2457116d";
  static vapi_message_desc_t __vapi_metadata_add_node_next = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_add_node_next, payload),
    (verify_msg_size_fn_t)vapi_verify_add_node_next_msg_size,
    (generic_swap_fn_t)vapi_msg_add_node_next_hton,
    (generic_swap_fn_t)vapi_msg_add_node_next_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_add_node_next = vapi_register_msg(&__vapi_metadata_add_node_next);
  VAPI_DBG("Assigned msg id %d to add_node_next", vapi_msg_id_add_node_next);
}
#endif

#ifndef defined_vapi_msg_show_threads_reply
#define defined_vapi_msg_show_threads_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 count;
  vapi_type_thread_data thread_data[0]; 
} vapi_payload_show_threads_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_threads_reply payload;
} vapi_msg_show_threads_reply;

static inline void vapi_msg_show_threads_reply_payload_hton(vapi_payload_show_threads_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->count = htobe32(payload->count);
  do { unsigned i; for (i = 0; i < be32toh(payload->count); ++i) { vapi_type_thread_data_hton(&payload->thread_data[i]); } } while(0);
}

static inline void vapi_msg_show_threads_reply_payload_ntoh(vapi_payload_show_threads_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->count = be32toh(payload->count);
  do { unsigned i; for (i = 0; i < payload->count; ++i) { vapi_type_thread_data_ntoh(&payload->thread_data[i]); } } while(0);
}

static inline void vapi_msg_show_threads_reply_hton(vapi_msg_show_threads_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_threads_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_threads_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_threads_reply_ntoh(vapi_msg_show_threads_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_threads_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_threads_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_threads_reply_msg_size(vapi_msg_show_threads_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.thread_data[0]) * msg->payload.count;
}

static inline int vapi_verify_show_threads_reply_msg_size(vapi_msg_show_threads_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_threads_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_threads_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_threads_reply));
      return -1;
    }
  if (vapi_calc_show_threads_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_threads_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_threads_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_threads_reply()
{
  static const char name[] = "show_threads_reply";
  static const char name_with_crc[] = "show_threads_reply_efd78e83";
  static vapi_message_desc_t __vapi_metadata_show_threads_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_threads_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_threads_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_threads_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_threads_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_threads_reply = vapi_register_msg(&__vapi_metadata_show_threads_reply);
  VAPI_DBG("Assigned msg id %d to show_threads_reply", vapi_msg_id_show_threads_reply);
}

static inline void vapi_set_vapi_msg_show_threads_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_threads_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_threads_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_threads
#define defined_vapi_msg_show_threads
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_threads;

static inline void vapi_msg_show_threads_hton(vapi_msg_show_threads *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_threads'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_threads_ntoh(vapi_msg_show_threads *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_threads'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_threads_msg_size(vapi_msg_show_threads *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_threads_msg_size(vapi_msg_show_threads *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_threads) > buf_size)
    {
      VAPI_ERR("Truncated 'show_threads' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_threads));
      return -1;
    }
  if (vapi_calc_show_threads_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_threads' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_threads_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_threads* vapi_alloc_show_threads(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_threads *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_threads);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_threads*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_threads);

  return msg;
}

static inline vapi_error_e vapi_show_threads(struct vapi_ctx_s *ctx,
  vapi_msg_show_threads *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_threads_reply *reply),
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
  vapi_msg_show_threads_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_threads_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_threads_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_threads()
{
  static const char name[] = "show_threads";
  static const char name_with_crc[] = "show_threads_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_threads = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_threads_msg_size,
    (generic_swap_fn_t)vapi_msg_show_threads_hton,
    (generic_swap_fn_t)vapi_msg_show_threads_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_threads = vapi_register_msg(&__vapi_metadata_show_threads);
  VAPI_DBG("Assigned msg id %d to show_threads", vapi_msg_id_show_threads);
}
#endif

#ifndef defined_vapi_msg_get_node_graph_reply
#define defined_vapi_msg_get_node_graph_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u64 reply_in_shmem; 
} vapi_payload_get_node_graph_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_node_graph_reply payload;
} vapi_msg_get_node_graph_reply;

static inline void vapi_msg_get_node_graph_reply_payload_hton(vapi_payload_get_node_graph_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->reply_in_shmem = htobe64(payload->reply_in_shmem);
}

static inline void vapi_msg_get_node_graph_reply_payload_ntoh(vapi_payload_get_node_graph_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->reply_in_shmem = be64toh(payload->reply_in_shmem);
}

static inline void vapi_msg_get_node_graph_reply_hton(vapi_msg_get_node_graph_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_graph_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_node_graph_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_node_graph_reply_ntoh(vapi_msg_get_node_graph_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_graph_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_node_graph_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_node_graph_reply_msg_size(vapi_msg_get_node_graph_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_node_graph_reply_msg_size(vapi_msg_get_node_graph_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_node_graph_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_graph_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_node_graph_reply));
      return -1;
    }
  if (vapi_calc_get_node_graph_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_graph_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_node_graph_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_node_graph_reply()
{
  static const char name[] = "get_node_graph_reply";
  static const char name_with_crc[] = "get_node_graph_reply_06d68297";
  static vapi_message_desc_t __vapi_metadata_get_node_graph_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_node_graph_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_node_graph_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_node_graph_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_node_graph_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_node_graph_reply = vapi_register_msg(&__vapi_metadata_get_node_graph_reply);
  VAPI_DBG("Assigned msg id %d to get_node_graph_reply", vapi_msg_id_get_node_graph_reply);
}

static inline void vapi_set_vapi_msg_get_node_graph_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_node_graph_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_node_graph_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_node_graph
#define defined_vapi_msg_get_node_graph
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_get_node_graph;

static inline void vapi_msg_get_node_graph_hton(vapi_msg_get_node_graph *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_graph'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_get_node_graph_ntoh(vapi_msg_get_node_graph *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_node_graph'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_get_node_graph_msg_size(vapi_msg_get_node_graph *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_node_graph_msg_size(vapi_msg_get_node_graph *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_node_graph) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_graph' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_node_graph));
      return -1;
    }
  if (vapi_calc_get_node_graph_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_node_graph' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_node_graph_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_node_graph* vapi_alloc_get_node_graph(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_node_graph *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_node_graph);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_node_graph*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_node_graph);

  return msg;
}

static inline vapi_error_e vapi_get_node_graph(struct vapi_ctx_s *ctx,
  vapi_msg_get_node_graph *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_node_graph_reply *reply),
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
  vapi_msg_get_node_graph_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_node_graph_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_node_graph_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_node_graph()
{
  static const char name[] = "get_node_graph";
  static const char name_with_crc[] = "get_node_graph_51077d14";
  static vapi_message_desc_t __vapi_metadata_get_node_graph = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_get_node_graph_msg_size,
    (generic_swap_fn_t)vapi_msg_get_node_graph_hton,
    (generic_swap_fn_t)vapi_msg_get_node_graph_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_node_graph = vapi_register_msg(&__vapi_metadata_get_node_graph);
  VAPI_DBG("Assigned msg id %d to get_node_graph", vapi_msg_id_get_node_graph);
}
#endif

#ifndef defined_vapi_msg_get_next_index_reply
#define defined_vapi_msg_get_next_index_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 next_index; 
} vapi_payload_get_next_index_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_next_index_reply payload;
} vapi_msg_get_next_index_reply;

static inline void vapi_msg_get_next_index_reply_payload_hton(vapi_payload_get_next_index_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->next_index = htobe32(payload->next_index);
}

static inline void vapi_msg_get_next_index_reply_payload_ntoh(vapi_payload_get_next_index_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->next_index = be32toh(payload->next_index);
}

static inline void vapi_msg_get_next_index_reply_hton(vapi_msg_get_next_index_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_next_index_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_next_index_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_next_index_reply_ntoh(vapi_msg_get_next_index_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_next_index_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_next_index_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_next_index_reply_msg_size(vapi_msg_get_next_index_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_next_index_reply_msg_size(vapi_msg_get_next_index_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_next_index_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_next_index_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_next_index_reply));
      return -1;
    }
  if (vapi_calc_get_next_index_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_next_index_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_next_index_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_next_index_reply()
{
  static const char name[] = "get_next_index_reply";
  static const char name_with_crc[] = "get_next_index_reply_2ed75f32";
  static vapi_message_desc_t __vapi_metadata_get_next_index_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_next_index_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_next_index_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_next_index_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_next_index_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_next_index_reply = vapi_register_msg(&__vapi_metadata_get_next_index_reply);
  VAPI_DBG("Assigned msg id %d to get_next_index_reply", vapi_msg_id_get_next_index_reply);
}

static inline void vapi_set_vapi_msg_get_next_index_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_next_index_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_next_index_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_next_index
#define defined_vapi_msg_get_next_index
typedef struct __attribute__ ((__packed__)) {
  u8 node_name[64];
  u8 next_name[64]; 
} vapi_payload_get_next_index;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_get_next_index payload;
} vapi_msg_get_next_index;

static inline void vapi_msg_get_next_index_payload_hton(vapi_payload_get_next_index *payload)
{

}

static inline void vapi_msg_get_next_index_payload_ntoh(vapi_payload_get_next_index *payload)
{

}

static inline void vapi_msg_get_next_index_hton(vapi_msg_get_next_index *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_next_index'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_get_next_index_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_next_index_ntoh(vapi_msg_get_next_index *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_next_index'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_get_next_index_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_next_index_msg_size(vapi_msg_get_next_index *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_next_index_msg_size(vapi_msg_get_next_index *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_next_index) > buf_size)
    {
      VAPI_ERR("Truncated 'get_next_index' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_next_index));
      return -1;
    }
  if (vapi_calc_get_next_index_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_next_index' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_next_index_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_next_index* vapi_alloc_get_next_index(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_next_index *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_next_index);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_next_index*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_next_index);

  return msg;
}

static inline vapi_error_e vapi_get_next_index(struct vapi_ctx_s *ctx,
  vapi_msg_get_next_index *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_next_index_reply *reply),
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
  vapi_msg_get_next_index_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_next_index_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_next_index_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_next_index()
{
  static const char name[] = "get_next_index";
  static const char name_with_crc[] = "get_next_index_2457116d";
  static vapi_message_desc_t __vapi_metadata_get_next_index = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_get_next_index, payload),
    (verify_msg_size_fn_t)vapi_verify_get_next_index_msg_size,
    (generic_swap_fn_t)vapi_msg_get_next_index_hton,
    (generic_swap_fn_t)vapi_msg_get_next_index_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_next_index = vapi_register_msg(&__vapi_metadata_get_next_index);
  VAPI_DBG("Assigned msg id %d to get_next_index", vapi_msg_id_get_next_index);
}
#endif

#ifndef defined_vapi_msg_get_f64_endian_value_reply
#define defined_vapi_msg_get_f64_endian_value_reply
typedef struct __attribute__ ((__packed__)) {
  u32 retval;
  f64 f64_one_result; 
} vapi_payload_get_f64_endian_value_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_f64_endian_value_reply payload;
} vapi_msg_get_f64_endian_value_reply;

static inline void vapi_msg_get_f64_endian_value_reply_payload_hton(vapi_payload_get_f64_endian_value_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_get_f64_endian_value_reply_payload_ntoh(vapi_payload_get_f64_endian_value_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_get_f64_endian_value_reply_hton(vapi_msg_get_f64_endian_value_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_endian_value_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_f64_endian_value_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_f64_endian_value_reply_ntoh(vapi_msg_get_f64_endian_value_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_endian_value_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_f64_endian_value_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_f64_endian_value_reply_msg_size(vapi_msg_get_f64_endian_value_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_f64_endian_value_reply_msg_size(vapi_msg_get_f64_endian_value_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_f64_endian_value_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_endian_value_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_f64_endian_value_reply));
      return -1;
    }
  if (vapi_calc_get_f64_endian_value_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_endian_value_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_f64_endian_value_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_f64_endian_value_reply()
{
  static const char name[] = "get_f64_endian_value_reply";
  static const char name_with_crc[] = "get_f64_endian_value_reply_7e02e404";
  static vapi_message_desc_t __vapi_metadata_get_f64_endian_value_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_f64_endian_value_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_f64_endian_value_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_f64_endian_value_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_f64_endian_value_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_f64_endian_value_reply = vapi_register_msg(&__vapi_metadata_get_f64_endian_value_reply);
  VAPI_DBG("Assigned msg id %d to get_f64_endian_value_reply", vapi_msg_id_get_f64_endian_value_reply);
}

static inline void vapi_set_vapi_msg_get_f64_endian_value_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_f64_endian_value_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_f64_endian_value_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_f64_endian_value
#define defined_vapi_msg_get_f64_endian_value
typedef struct __attribute__ ((__packed__)) {
  f64 f64_one; 
} vapi_payload_get_f64_endian_value;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_get_f64_endian_value payload;
} vapi_msg_get_f64_endian_value;

static inline void vapi_msg_get_f64_endian_value_payload_hton(vapi_payload_get_f64_endian_value *payload)
{

}

static inline void vapi_msg_get_f64_endian_value_payload_ntoh(vapi_payload_get_f64_endian_value *payload)
{

}

static inline void vapi_msg_get_f64_endian_value_hton(vapi_msg_get_f64_endian_value *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_endian_value'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_get_f64_endian_value_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_f64_endian_value_ntoh(vapi_msg_get_f64_endian_value *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_endian_value'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_get_f64_endian_value_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_f64_endian_value_msg_size(vapi_msg_get_f64_endian_value *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_f64_endian_value_msg_size(vapi_msg_get_f64_endian_value *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_f64_endian_value) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_endian_value' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_f64_endian_value));
      return -1;
    }
  if (vapi_calc_get_f64_endian_value_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_endian_value' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_f64_endian_value_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_f64_endian_value* vapi_alloc_get_f64_endian_value(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_f64_endian_value *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_f64_endian_value);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_f64_endian_value*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_f64_endian_value);

  return msg;
}

static inline vapi_error_e vapi_get_f64_endian_value(struct vapi_ctx_s *ctx,
  vapi_msg_get_f64_endian_value *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_f64_endian_value_reply *reply),
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
  vapi_msg_get_f64_endian_value_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_f64_endian_value_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_f64_endian_value_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_f64_endian_value()
{
  static const char name[] = "get_f64_endian_value";
  static const char name_with_crc[] = "get_f64_endian_value_809fcd44";
  static vapi_message_desc_t __vapi_metadata_get_f64_endian_value = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_get_f64_endian_value, payload),
    (verify_msg_size_fn_t)vapi_verify_get_f64_endian_value_msg_size,
    (generic_swap_fn_t)vapi_msg_get_f64_endian_value_hton,
    (generic_swap_fn_t)vapi_msg_get_f64_endian_value_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_f64_endian_value = vapi_register_msg(&__vapi_metadata_get_f64_endian_value);
  VAPI_DBG("Assigned msg id %d to get_f64_endian_value", vapi_msg_id_get_f64_endian_value);
}
#endif

#ifndef defined_vapi_msg_get_f64_increment_by_one_reply
#define defined_vapi_msg_get_f64_increment_by_one_reply
typedef struct __attribute__ ((__packed__)) {
  u32 retval;
  f64 f64_value; 
} vapi_payload_get_f64_increment_by_one_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_get_f64_increment_by_one_reply payload;
} vapi_msg_get_f64_increment_by_one_reply;

static inline void vapi_msg_get_f64_increment_by_one_reply_payload_hton(vapi_payload_get_f64_increment_by_one_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_get_f64_increment_by_one_reply_payload_ntoh(vapi_payload_get_f64_increment_by_one_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_get_f64_increment_by_one_reply_hton(vapi_msg_get_f64_increment_by_one_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_increment_by_one_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_get_f64_increment_by_one_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_f64_increment_by_one_reply_ntoh(vapi_msg_get_f64_increment_by_one_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_increment_by_one_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_get_f64_increment_by_one_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_f64_increment_by_one_reply_msg_size(vapi_msg_get_f64_increment_by_one_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_f64_increment_by_one_reply_msg_size(vapi_msg_get_f64_increment_by_one_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_f64_increment_by_one_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_increment_by_one_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_f64_increment_by_one_reply));
      return -1;
    }
  if (vapi_calc_get_f64_increment_by_one_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_increment_by_one_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_f64_increment_by_one_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_get_f64_increment_by_one_reply()
{
  static const char name[] = "get_f64_increment_by_one_reply";
  static const char name_with_crc[] = "get_f64_increment_by_one_reply_d25dbaa3";
  static vapi_message_desc_t __vapi_metadata_get_f64_increment_by_one_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_get_f64_increment_by_one_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_get_f64_increment_by_one_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_get_f64_increment_by_one_reply_hton,
    (generic_swap_fn_t)vapi_msg_get_f64_increment_by_one_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_f64_increment_by_one_reply = vapi_register_msg(&__vapi_metadata_get_f64_increment_by_one_reply);
  VAPI_DBG("Assigned msg id %d to get_f64_increment_by_one_reply", vapi_msg_id_get_f64_increment_by_one_reply);
}

static inline void vapi_set_vapi_msg_get_f64_increment_by_one_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_get_f64_increment_by_one_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_get_f64_increment_by_one_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_get_f64_increment_by_one
#define defined_vapi_msg_get_f64_increment_by_one
typedef struct __attribute__ ((__packed__)) {
  f64 f64_value; 
} vapi_payload_get_f64_increment_by_one;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_get_f64_increment_by_one payload;
} vapi_msg_get_f64_increment_by_one;

static inline void vapi_msg_get_f64_increment_by_one_payload_hton(vapi_payload_get_f64_increment_by_one *payload)
{

}

static inline void vapi_msg_get_f64_increment_by_one_payload_ntoh(vapi_payload_get_f64_increment_by_one *payload)
{

}

static inline void vapi_msg_get_f64_increment_by_one_hton(vapi_msg_get_f64_increment_by_one *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_increment_by_one'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_get_f64_increment_by_one_payload_hton(&msg->payload);
}

static inline void vapi_msg_get_f64_increment_by_one_ntoh(vapi_msg_get_f64_increment_by_one *msg)
{
  VAPI_DBG("Swapping `vapi_msg_get_f64_increment_by_one'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_get_f64_increment_by_one_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_get_f64_increment_by_one_msg_size(vapi_msg_get_f64_increment_by_one *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_get_f64_increment_by_one_msg_size(vapi_msg_get_f64_increment_by_one *msg, uword buf_size)
{
  if (sizeof(vapi_msg_get_f64_increment_by_one) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_increment_by_one' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_get_f64_increment_by_one));
      return -1;
    }
  if (vapi_calc_get_f64_increment_by_one_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'get_f64_increment_by_one' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_get_f64_increment_by_one_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_get_f64_increment_by_one* vapi_alloc_get_f64_increment_by_one(struct vapi_ctx_s *ctx)
{
  vapi_msg_get_f64_increment_by_one *msg = NULL;
  const size_t size = sizeof(vapi_msg_get_f64_increment_by_one);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_get_f64_increment_by_one*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_get_f64_increment_by_one);

  return msg;
}

static inline vapi_error_e vapi_get_f64_increment_by_one(struct vapi_ctx_s *ctx,
  vapi_msg_get_f64_increment_by_one *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_get_f64_increment_by_one_reply *reply),
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
  vapi_msg_get_f64_increment_by_one_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_get_f64_increment_by_one_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_get_f64_increment_by_one_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_get_f64_increment_by_one()
{
  static const char name[] = "get_f64_increment_by_one";
  static const char name_with_crc[] = "get_f64_increment_by_one_b64f027e";
  static vapi_message_desc_t __vapi_metadata_get_f64_increment_by_one = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_get_f64_increment_by_one, payload),
    (verify_msg_size_fn_t)vapi_verify_get_f64_increment_by_one_msg_size,
    (generic_swap_fn_t)vapi_msg_get_f64_increment_by_one_hton,
    (generic_swap_fn_t)vapi_msg_get_f64_increment_by_one_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_get_f64_increment_by_one = vapi_register_msg(&__vapi_metadata_get_f64_increment_by_one);
  VAPI_DBG("Assigned msg id %d to get_f64_increment_by_one", vapi_msg_id_get_f64_increment_by_one);
}
#endif



static inline vapi_error_e
vapi_send_with_control_ping (vapi_ctx_t ctx, void *msg, u32 context)
{
  vapi_msg_control_ping *ping = vapi_alloc_control_ping (ctx);
  if (!ping)
    {
      return VAPI_ENOMEM;
    }
  ping->header.context = context;
  vapi_msg_control_ping_hton (ping);
  return vapi_send2 (ctx, msg, ping);
}


#ifdef __cplusplus
}
#endif

#endif
