#ifndef __included_selog_api_json
#define __included_selog_api_json

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

extern vapi_msg_id_t vapi_msg_id_selog_get_shm;
extern vapi_msg_id_t vapi_msg_id_selog_get_shm_reply;
extern vapi_msg_id_t vapi_msg_id_selog_get_string_table;
extern vapi_msg_id_t vapi_msg_id_selog_get_string_table_reply;
extern vapi_msg_id_t vapi_msg_id_selog_track_dump;
extern vapi_msg_id_t vapi_msg_id_selog_track_details;
extern vapi_msg_id_t vapi_msg_id_selog_event_type_dump;
extern vapi_msg_id_t vapi_msg_id_selog_event_type_details;
extern vapi_msg_id_t vapi_msg_id_selog_event_type_string_dump;
extern vapi_msg_id_t vapi_msg_id_selog_event_type_string_details;

#define DEFINE_VAPI_MSG_IDS_SELOG_API_JSON\
  vapi_msg_id_t vapi_msg_id_selog_get_shm;\
  vapi_msg_id_t vapi_msg_id_selog_get_shm_reply;\
  vapi_msg_id_t vapi_msg_id_selog_get_string_table;\
  vapi_msg_id_t vapi_msg_id_selog_get_string_table_reply;\
  vapi_msg_id_t vapi_msg_id_selog_track_dump;\
  vapi_msg_id_t vapi_msg_id_selog_track_details;\
  vapi_msg_id_t vapi_msg_id_selog_event_type_dump;\
  vapi_msg_id_t vapi_msg_id_selog_event_type_details;\
  vapi_msg_id_t vapi_msg_id_selog_event_type_string_dump;\
  vapi_msg_id_t vapi_msg_id_selog_event_type_string_details;


#ifndef defined_vapi_msg_selog_get_shm_reply
#define defined_vapi_msg_selog_get_shm_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_selog_get_shm_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_selog_get_shm_reply payload;
} vapi_msg_selog_get_shm_reply;

static inline void vapi_msg_selog_get_shm_reply_payload_hton(vapi_payload_selog_get_shm_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_selog_get_shm_reply_payload_ntoh(vapi_payload_selog_get_shm_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_selog_get_shm_reply_hton(vapi_msg_selog_get_shm_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_shm_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_selog_get_shm_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_get_shm_reply_ntoh(vapi_msg_selog_get_shm_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_shm_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_selog_get_shm_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_get_shm_reply_msg_size(vapi_msg_selog_get_shm_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_get_shm_reply_msg_size(vapi_msg_selog_get_shm_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_get_shm_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_shm_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_get_shm_reply));
      return -1;
    }
  if (vapi_calc_selog_get_shm_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_shm_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_get_shm_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_selog_get_shm_reply()
{
  static const char name[] = "selog_get_shm_reply";
  static const char name_with_crc[] = "selog_get_shm_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_selog_get_shm_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_selog_get_shm_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_get_shm_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_get_shm_reply_hton,
    (generic_swap_fn_t)vapi_msg_selog_get_shm_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_get_shm_reply = vapi_register_msg(&__vapi_metadata_selog_get_shm_reply);
  VAPI_DBG("Assigned msg id %d to selog_get_shm_reply", vapi_msg_id_selog_get_shm_reply);
}

static inline void vapi_set_vapi_msg_selog_get_shm_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_selog_get_shm_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_selog_get_shm_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_selog_get_shm
#define defined_vapi_msg_selog_get_shm
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_selog_get_shm;

static inline void vapi_msg_selog_get_shm_hton(vapi_msg_selog_get_shm *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_shm'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_selog_get_shm_ntoh(vapi_msg_selog_get_shm *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_shm'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_selog_get_shm_msg_size(vapi_msg_selog_get_shm *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_get_shm_msg_size(vapi_msg_selog_get_shm *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_get_shm) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_shm' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_get_shm));
      return -1;
    }
  if (vapi_calc_selog_get_shm_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_shm' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_get_shm_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_selog_get_shm* vapi_alloc_selog_get_shm(struct vapi_ctx_s *ctx)
{
  vapi_msg_selog_get_shm *msg = NULL;
  const size_t size = sizeof(vapi_msg_selog_get_shm);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_selog_get_shm*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_selog_get_shm);

  return msg;
}

static inline vapi_error_e vapi_selog_get_shm(struct vapi_ctx_s *ctx,
  vapi_msg_selog_get_shm *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_selog_get_shm_reply *reply),
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
  vapi_msg_selog_get_shm_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_selog_get_shm_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_selog_get_shm_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_selog_get_shm()
{
  static const char name[] = "selog_get_shm";
  static const char name_with_crc[] = "selog_get_shm_51077d14";
  static vapi_message_desc_t __vapi_metadata_selog_get_shm = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_selog_get_shm_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_get_shm_hton,
    (generic_swap_fn_t)vapi_msg_selog_get_shm_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_get_shm = vapi_register_msg(&__vapi_metadata_selog_get_shm);
  VAPI_DBG("Assigned msg id %d to selog_get_shm", vapi_msg_id_selog_get_shm);
}
#endif

#ifndef defined_vapi_msg_selog_get_string_table_reply
#define defined_vapi_msg_selog_get_string_table_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vl_api_string_t s; 
} vapi_payload_selog_get_string_table_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_selog_get_string_table_reply payload;
} vapi_msg_selog_get_string_table_reply;

static inline void vapi_msg_selog_get_string_table_reply_payload_hton(vapi_payload_selog_get_string_table_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  vl_api_string_t_hton(&payload->s);
}

static inline void vapi_msg_selog_get_string_table_reply_payload_ntoh(vapi_payload_selog_get_string_table_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  vl_api_string_t_ntoh(&payload->s);
}

static inline void vapi_msg_selog_get_string_table_reply_hton(vapi_msg_selog_get_string_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_string_table_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_selog_get_string_table_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_get_string_table_reply_ntoh(vapi_msg_selog_get_string_table_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_string_table_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_selog_get_string_table_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_get_string_table_reply_msg_size(vapi_msg_selog_get_string_table_reply *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.s.buf[0]) * msg->payload.s.length;
}

static inline int vapi_verify_selog_get_string_table_reply_msg_size(vapi_msg_selog_get_string_table_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_get_string_table_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_string_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_get_string_table_reply));
      return -1;
    }
  if (vapi_calc_selog_get_string_table_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_string_table_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_get_string_table_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_selog_get_string_table_reply()
{
  static const char name[] = "selog_get_string_table_reply";
  static const char name_with_crc[] = "selog_get_string_table_reply_17fc26aa";
  static vapi_message_desc_t __vapi_metadata_selog_get_string_table_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_selog_get_string_table_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_get_string_table_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_get_string_table_reply_hton,
    (generic_swap_fn_t)vapi_msg_selog_get_string_table_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_get_string_table_reply = vapi_register_msg(&__vapi_metadata_selog_get_string_table_reply);
  VAPI_DBG("Assigned msg id %d to selog_get_string_table_reply", vapi_msg_id_selog_get_string_table_reply);
}

static inline void vapi_set_vapi_msg_selog_get_string_table_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_selog_get_string_table_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_selog_get_string_table_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_selog_get_string_table
#define defined_vapi_msg_selog_get_string_table
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_selog_get_string_table;

static inline void vapi_msg_selog_get_string_table_hton(vapi_msg_selog_get_string_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_string_table'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_selog_get_string_table_ntoh(vapi_msg_selog_get_string_table *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_get_string_table'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_selog_get_string_table_msg_size(vapi_msg_selog_get_string_table *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_get_string_table_msg_size(vapi_msg_selog_get_string_table *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_get_string_table) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_string_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_get_string_table));
      return -1;
    }
  if (vapi_calc_selog_get_string_table_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_get_string_table' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_get_string_table_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_selog_get_string_table* vapi_alloc_selog_get_string_table(struct vapi_ctx_s *ctx)
{
  vapi_msg_selog_get_string_table *msg = NULL;
  const size_t size = sizeof(vapi_msg_selog_get_string_table);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_selog_get_string_table*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_selog_get_string_table);

  return msg;
}

static inline vapi_error_e vapi_selog_get_string_table(struct vapi_ctx_s *ctx,
  vapi_msg_selog_get_string_table *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_selog_get_string_table_reply *reply),
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
  vapi_msg_selog_get_string_table_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_selog_get_string_table_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_selog_get_string_table_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_selog_get_string_table()
{
  static const char name[] = "selog_get_string_table";
  static const char name_with_crc[] = "selog_get_string_table_51077d14";
  static vapi_message_desc_t __vapi_metadata_selog_get_string_table = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_selog_get_string_table_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_get_string_table_hton,
    (generic_swap_fn_t)vapi_msg_selog_get_string_table_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_get_string_table = vapi_register_msg(&__vapi_metadata_selog_get_string_table);
  VAPI_DBG("Assigned msg id %d to selog_get_string_table", vapi_msg_id_selog_get_string_table);
}
#endif

#ifndef defined_vapi_msg_selog_track_details
#define defined_vapi_msg_selog_track_details
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  vl_api_string_t name; 
} vapi_payload_selog_track_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_selog_track_details payload;
} vapi_msg_selog_track_details;

static inline void vapi_msg_selog_track_details_payload_hton(vapi_payload_selog_track_details *payload)
{
  payload->index = htobe32(payload->index);
  vl_api_string_t_hton(&payload->name);
}

static inline void vapi_msg_selog_track_details_payload_ntoh(vapi_payload_selog_track_details *payload)
{
  payload->index = be32toh(payload->index);
  vl_api_string_t_ntoh(&payload->name);
}

static inline void vapi_msg_selog_track_details_hton(vapi_msg_selog_track_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_track_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_selog_track_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_track_details_ntoh(vapi_msg_selog_track_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_track_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_selog_track_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_track_details_msg_size(vapi_msg_selog_track_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.name.buf[0]) * msg->payload.name.length;
}

static inline int vapi_verify_selog_track_details_msg_size(vapi_msg_selog_track_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_track_details) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_track_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_track_details));
      return -1;
    }
  if (vapi_calc_selog_track_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_track_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_track_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_selog_track_details()
{
  static const char name[] = "selog_track_details";
  static const char name_with_crc[] = "selog_track_details_33dce766";
  static vapi_message_desc_t __vapi_metadata_selog_track_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_selog_track_details, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_track_details_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_track_details_hton,
    (generic_swap_fn_t)vapi_msg_selog_track_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_track_details = vapi_register_msg(&__vapi_metadata_selog_track_details);
  VAPI_DBG("Assigned msg id %d to selog_track_details", vapi_msg_id_selog_track_details);
}

static inline void vapi_set_vapi_msg_selog_track_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_selog_track_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_selog_track_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_selog_track_dump
#define defined_vapi_msg_selog_track_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_selog_track_dump;

static inline void vapi_msg_selog_track_dump_hton(vapi_msg_selog_track_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_track_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_selog_track_dump_ntoh(vapi_msg_selog_track_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_track_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_selog_track_dump_msg_size(vapi_msg_selog_track_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_track_dump_msg_size(vapi_msg_selog_track_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_track_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_track_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_track_dump));
      return -1;
    }
  if (vapi_calc_selog_track_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_track_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_track_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_selog_track_dump* vapi_alloc_selog_track_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_selog_track_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_selog_track_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_selog_track_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_selog_track_dump);

  return msg;
}

static inline vapi_error_e vapi_selog_track_dump(struct vapi_ctx_s *ctx,
  vapi_msg_selog_track_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_selog_track_details *reply),
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
  vapi_msg_selog_track_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_selog_track_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_selog_track_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_selog_track_dump()
{
  static const char name[] = "selog_track_dump";
  static const char name_with_crc[] = "selog_track_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_selog_track_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_selog_track_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_track_dump_hton,
    (generic_swap_fn_t)vapi_msg_selog_track_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_track_dump = vapi_register_msg(&__vapi_metadata_selog_track_dump);
  VAPI_DBG("Assigned msg id %d to selog_track_dump", vapi_msg_id_selog_track_dump);
}
#endif

#ifndef defined_vapi_msg_selog_event_type_details
#define defined_vapi_msg_selog_event_type_details
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  u8 fmt_args[32];
  vl_api_string_t fmt; 
} vapi_payload_selog_event_type_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_selog_event_type_details payload;
} vapi_msg_selog_event_type_details;

static inline void vapi_msg_selog_event_type_details_payload_hton(vapi_payload_selog_event_type_details *payload)
{
  payload->index = htobe32(payload->index);
  vl_api_string_t_hton(&payload->fmt);
}

static inline void vapi_msg_selog_event_type_details_payload_ntoh(vapi_payload_selog_event_type_details *payload)
{
  payload->index = be32toh(payload->index);
  vl_api_string_t_ntoh(&payload->fmt);
}

static inline void vapi_msg_selog_event_type_details_hton(vapi_msg_selog_event_type_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_selog_event_type_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_event_type_details_ntoh(vapi_msg_selog_event_type_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_selog_event_type_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_event_type_details_msg_size(vapi_msg_selog_event_type_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.fmt.buf[0]) * msg->payload.fmt.length;
}

static inline int vapi_verify_selog_event_type_details_msg_size(vapi_msg_selog_event_type_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_event_type_details) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_event_type_details));
      return -1;
    }
  if (vapi_calc_selog_event_type_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_event_type_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_selog_event_type_details()
{
  static const char name[] = "selog_event_type_details";
  static const char name_with_crc[] = "selog_event_type_details_745bca80";
  static vapi_message_desc_t __vapi_metadata_selog_event_type_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_selog_event_type_details, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_event_type_details_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_event_type_details_hton,
    (generic_swap_fn_t)vapi_msg_selog_event_type_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_event_type_details = vapi_register_msg(&__vapi_metadata_selog_event_type_details);
  VAPI_DBG("Assigned msg id %d to selog_event_type_details", vapi_msg_id_selog_event_type_details);
}

static inline void vapi_set_vapi_msg_selog_event_type_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_selog_event_type_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_selog_event_type_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_selog_event_type_dump
#define defined_vapi_msg_selog_event_type_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_selog_event_type_dump;

static inline void vapi_msg_selog_event_type_dump_hton(vapi_msg_selog_event_type_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_selog_event_type_dump_ntoh(vapi_msg_selog_event_type_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_selog_event_type_dump_msg_size(vapi_msg_selog_event_type_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_event_type_dump_msg_size(vapi_msg_selog_event_type_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_event_type_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_event_type_dump));
      return -1;
    }
  if (vapi_calc_selog_event_type_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_event_type_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_selog_event_type_dump* vapi_alloc_selog_event_type_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_selog_event_type_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_selog_event_type_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_selog_event_type_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_selog_event_type_dump);

  return msg;
}

static inline vapi_error_e vapi_selog_event_type_dump(struct vapi_ctx_s *ctx,
  vapi_msg_selog_event_type_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_selog_event_type_details *reply),
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
  vapi_msg_selog_event_type_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_selog_event_type_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_selog_event_type_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_selog_event_type_dump()
{
  static const char name[] = "selog_event_type_dump";
  static const char name_with_crc[] = "selog_event_type_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_selog_event_type_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_selog_event_type_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_event_type_dump_hton,
    (generic_swap_fn_t)vapi_msg_selog_event_type_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_event_type_dump = vapi_register_msg(&__vapi_metadata_selog_event_type_dump);
  VAPI_DBG("Assigned msg id %d to selog_event_type_dump", vapi_msg_id_selog_event_type_dump);
}
#endif

#ifndef defined_vapi_msg_selog_event_type_string_details
#define defined_vapi_msg_selog_event_type_string_details
typedef struct __attribute__ ((__packed__)) {
  u32 index;
  vl_api_string_t s; 
} vapi_payload_selog_event_type_string_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_selog_event_type_string_details payload;
} vapi_msg_selog_event_type_string_details;

static inline void vapi_msg_selog_event_type_string_details_payload_hton(vapi_payload_selog_event_type_string_details *payload)
{
  payload->index = htobe32(payload->index);
  vl_api_string_t_hton(&payload->s);
}

static inline void vapi_msg_selog_event_type_string_details_payload_ntoh(vapi_payload_selog_event_type_string_details *payload)
{
  payload->index = be32toh(payload->index);
  vl_api_string_t_ntoh(&payload->s);
}

static inline void vapi_msg_selog_event_type_string_details_hton(vapi_msg_selog_event_type_string_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_string_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_selog_event_type_string_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_event_type_string_details_ntoh(vapi_msg_selog_event_type_string_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_string_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_selog_event_type_string_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_event_type_string_details_msg_size(vapi_msg_selog_event_type_string_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.s.buf[0]) * msg->payload.s.length;
}

static inline int vapi_verify_selog_event_type_string_details_msg_size(vapi_msg_selog_event_type_string_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_event_type_string_details) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_string_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_event_type_string_details));
      return -1;
    }
  if (vapi_calc_selog_event_type_string_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_string_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_event_type_string_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_selog_event_type_string_details()
{
  static const char name[] = "selog_event_type_string_details";
  static const char name_with_crc[] = "selog_event_type_string_details_3718921d";
  static vapi_message_desc_t __vapi_metadata_selog_event_type_string_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_selog_event_type_string_details, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_event_type_string_details_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_event_type_string_details_hton,
    (generic_swap_fn_t)vapi_msg_selog_event_type_string_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_event_type_string_details = vapi_register_msg(&__vapi_metadata_selog_event_type_string_details);
  VAPI_DBG("Assigned msg id %d to selog_event_type_string_details", vapi_msg_id_selog_event_type_string_details);
}

static inline void vapi_set_vapi_msg_selog_event_type_string_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_selog_event_type_string_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_selog_event_type_string_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_selog_event_type_string_dump
#define defined_vapi_msg_selog_event_type_string_dump
typedef struct __attribute__ ((__packed__)) {
  u32 event_type_index; 
} vapi_payload_selog_event_type_string_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_selog_event_type_string_dump payload;
} vapi_msg_selog_event_type_string_dump;

static inline void vapi_msg_selog_event_type_string_dump_payload_hton(vapi_payload_selog_event_type_string_dump *payload)
{
  payload->event_type_index = htobe32(payload->event_type_index);
}

static inline void vapi_msg_selog_event_type_string_dump_payload_ntoh(vapi_payload_selog_event_type_string_dump *payload)
{
  payload->event_type_index = be32toh(payload->event_type_index);
}

static inline void vapi_msg_selog_event_type_string_dump_hton(vapi_msg_selog_event_type_string_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_string_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_selog_event_type_string_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_selog_event_type_string_dump_ntoh(vapi_msg_selog_event_type_string_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_selog_event_type_string_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_selog_event_type_string_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_selog_event_type_string_dump_msg_size(vapi_msg_selog_event_type_string_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_selog_event_type_string_dump_msg_size(vapi_msg_selog_event_type_string_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_selog_event_type_string_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_string_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_selog_event_type_string_dump));
      return -1;
    }
  if (vapi_calc_selog_event_type_string_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'selog_event_type_string_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_selog_event_type_string_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_selog_event_type_string_dump* vapi_alloc_selog_event_type_string_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_selog_event_type_string_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_selog_event_type_string_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_selog_event_type_string_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_selog_event_type_string_dump);

  return msg;
}

static inline vapi_error_e vapi_selog_event_type_string_dump(struct vapi_ctx_s *ctx,
  vapi_msg_selog_event_type_string_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_selog_event_type_string_details *reply),
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
  vapi_msg_selog_event_type_string_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_selog_event_type_string_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_selog_event_type_string_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_selog_event_type_string_dump()
{
  static const char name[] = "selog_event_type_string_dump";
  static const char name_with_crc[] = "selog_event_type_string_dump_6a7f2680";
  static vapi_message_desc_t __vapi_metadata_selog_event_type_string_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_selog_event_type_string_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_selog_event_type_string_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_selog_event_type_string_dump_hton,
    (generic_swap_fn_t)vapi_msg_selog_event_type_string_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_selog_event_type_string_dump = vapi_register_msg(&__vapi_metadata_selog_event_type_string_dump);
  VAPI_DBG("Assigned msg id %d to selog_event_type_string_dump", vapi_msg_id_selog_event_type_string_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
