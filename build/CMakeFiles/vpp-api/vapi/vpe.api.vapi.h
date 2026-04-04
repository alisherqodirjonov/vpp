#ifndef __included_vpe_api_json
#define __included_vpe_api_json

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

extern vapi_msg_id_t vapi_msg_id_show_version;
extern vapi_msg_id_t vapi_msg_id_show_version_reply;
extern vapi_msg_id_t vapi_msg_id_show_vpe_system_time;
extern vapi_msg_id_t vapi_msg_id_show_vpe_system_time_reply;
extern vapi_msg_id_t vapi_msg_id_log_dump;
extern vapi_msg_id_t vapi_msg_id_log_details;

#define DEFINE_VAPI_MSG_IDS_VPE_API_JSON\
  vapi_msg_id_t vapi_msg_id_show_version;\
  vapi_msg_id_t vapi_msg_id_show_version_reply;\
  vapi_msg_id_t vapi_msg_id_show_vpe_system_time;\
  vapi_msg_id_t vapi_msg_id_show_vpe_system_time_reply;\
  vapi_msg_id_t vapi_msg_id_log_dump;\
  vapi_msg_id_t vapi_msg_id_log_details;


#ifndef defined_vapi_enum_log_level
#define defined_vapi_enum_log_level
typedef enum {
  VPE_API_LOG_LEVEL_EMERG = 0,
  VPE_API_LOG_LEVEL_ALERT = 1,
  VPE_API_LOG_LEVEL_CRIT = 2,
  VPE_API_LOG_LEVEL_ERR = 3,
  VPE_API_LOG_LEVEL_WARNING = 4,
  VPE_API_LOG_LEVEL_NOTICE = 5,
  VPE_API_LOG_LEVEL_INFO = 6,
  VPE_API_LOG_LEVEL_DEBUG = 7,
  VPE_API_LOG_LEVEL_DISABLED = 8,
}  vapi_enum_log_level;

#endif

#ifndef defined_vapi_type_version
#define defined_vapi_type_version
typedef struct __attribute__((__packed__)) {
  u32 major;
  u32 minor;
  u32 patch;
  u8 pre_release[17];
  u8 build_metadata[17];
} vapi_type_version;

static inline void vapi_type_version_hton(vapi_type_version *msg)
{
  msg->major = htobe32(msg->major);
  msg->minor = htobe32(msg->minor);
  msg->patch = htobe32(msg->patch);
}

static inline void vapi_type_version_ntoh(vapi_type_version *msg)
{
  msg->major = be32toh(msg->major);
  msg->minor = be32toh(msg->minor);
  msg->patch = be32toh(msg->patch);
}
#endif

#ifndef defined_vapi_type_timestamp
#define defined_vapi_type_timestamp
typedef f64 vapi_type_timestamp;

#endif

#ifndef defined_vapi_type_timedelta
#define defined_vapi_type_timedelta
typedef f64 vapi_type_timedelta;

#endif

#ifndef defined_vapi_msg_show_version_reply
#define defined_vapi_msg_show_version_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u8 program[32];
  u8 version[32];
  u8 build_date[32];
  u8 build_directory[256]; 
} vapi_payload_show_version_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_version_reply payload;
} vapi_msg_show_version_reply;

static inline void vapi_msg_show_version_reply_payload_hton(vapi_payload_show_version_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_version_reply_payload_ntoh(vapi_payload_show_version_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_version_reply_hton(vapi_msg_show_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_version_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_version_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_version_reply_ntoh(vapi_msg_show_version_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_version_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_version_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_version_reply_msg_size(vapi_msg_show_version_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_version_reply_msg_size(vapi_msg_show_version_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_version_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_version_reply));
      return -1;
    }
  if (vapi_calc_show_version_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_version_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_version_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_version_reply()
{
  static const char name[] = "show_version_reply";
  static const char name_with_crc[] = "show_version_reply_c919bde1";
  static vapi_message_desc_t __vapi_metadata_show_version_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_version_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_version_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_version_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_version_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_version_reply = vapi_register_msg(&__vapi_metadata_show_version_reply);
  VAPI_DBG("Assigned msg id %d to show_version_reply", vapi_msg_id_show_version_reply);
}

static inline void vapi_set_vapi_msg_show_version_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_version_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_version_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_version
#define defined_vapi_msg_show_version
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_version;

static inline void vapi_msg_show_version_hton(vapi_msg_show_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_version'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_version_ntoh(vapi_msg_show_version *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_version'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_version_msg_size(vapi_msg_show_version *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_version_msg_size(vapi_msg_show_version *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_version) > buf_size)
    {
      VAPI_ERR("Truncated 'show_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_version));
      return -1;
    }
  if (vapi_calc_show_version_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_version' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_version_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_version* vapi_alloc_show_version(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_version *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_version);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_version*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_version);

  return msg;
}

static inline vapi_error_e vapi_show_version(struct vapi_ctx_s *ctx,
  vapi_msg_show_version *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_version_reply *reply),
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
  vapi_msg_show_version_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_version_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_version_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_version()
{
  static const char name[] = "show_version";
  static const char name_with_crc[] = "show_version_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_version = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_version_msg_size,
    (generic_swap_fn_t)vapi_msg_show_version_hton,
    (generic_swap_fn_t)vapi_msg_show_version_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_version = vapi_register_msg(&__vapi_metadata_show_version);
  VAPI_DBG("Assigned msg id %d to show_version", vapi_msg_id_show_version);
}
#endif

#ifndef defined_vapi_msg_show_vpe_system_time_reply
#define defined_vapi_msg_show_vpe_system_time_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_timestamp vpe_system_time; 
} vapi_payload_show_vpe_system_time_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_show_vpe_system_time_reply payload;
} vapi_msg_show_vpe_system_time_reply;

static inline void vapi_msg_show_vpe_system_time_reply_payload_hton(vapi_payload_show_vpe_system_time_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_show_vpe_system_time_reply_payload_ntoh(vapi_payload_show_vpe_system_time_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_show_vpe_system_time_reply_hton(vapi_msg_show_vpe_system_time_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_vpe_system_time_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_show_vpe_system_time_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_show_vpe_system_time_reply_ntoh(vapi_msg_show_vpe_system_time_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_vpe_system_time_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_show_vpe_system_time_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_show_vpe_system_time_reply_msg_size(vapi_msg_show_vpe_system_time_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_vpe_system_time_reply_msg_size(vapi_msg_show_vpe_system_time_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_vpe_system_time_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'show_vpe_system_time_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_vpe_system_time_reply));
      return -1;
    }
  if (vapi_calc_show_vpe_system_time_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_vpe_system_time_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_vpe_system_time_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_show_vpe_system_time_reply()
{
  static const char name[] = "show_vpe_system_time_reply";
  static const char name_with_crc[] = "show_vpe_system_time_reply_7ffd8193";
  static vapi_message_desc_t __vapi_metadata_show_vpe_system_time_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_show_vpe_system_time_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_show_vpe_system_time_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_show_vpe_system_time_reply_hton,
    (generic_swap_fn_t)vapi_msg_show_vpe_system_time_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_vpe_system_time_reply = vapi_register_msg(&__vapi_metadata_show_vpe_system_time_reply);
  VAPI_DBG("Assigned msg id %d to show_vpe_system_time_reply", vapi_msg_id_show_vpe_system_time_reply);
}

static inline void vapi_set_vapi_msg_show_vpe_system_time_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_show_vpe_system_time_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_show_vpe_system_time_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_show_vpe_system_time
#define defined_vapi_msg_show_vpe_system_time
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_show_vpe_system_time;

static inline void vapi_msg_show_vpe_system_time_hton(vapi_msg_show_vpe_system_time *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_vpe_system_time'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_show_vpe_system_time_ntoh(vapi_msg_show_vpe_system_time *msg)
{
  VAPI_DBG("Swapping `vapi_msg_show_vpe_system_time'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_show_vpe_system_time_msg_size(vapi_msg_show_vpe_system_time *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_show_vpe_system_time_msg_size(vapi_msg_show_vpe_system_time *msg, uword buf_size)
{
  if (sizeof(vapi_msg_show_vpe_system_time) > buf_size)
    {
      VAPI_ERR("Truncated 'show_vpe_system_time' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_show_vpe_system_time));
      return -1;
    }
  if (vapi_calc_show_vpe_system_time_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'show_vpe_system_time' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_show_vpe_system_time_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_show_vpe_system_time* vapi_alloc_show_vpe_system_time(struct vapi_ctx_s *ctx)
{
  vapi_msg_show_vpe_system_time *msg = NULL;
  const size_t size = sizeof(vapi_msg_show_vpe_system_time);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_show_vpe_system_time*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_show_vpe_system_time);

  return msg;
}

static inline vapi_error_e vapi_show_vpe_system_time(struct vapi_ctx_s *ctx,
  vapi_msg_show_vpe_system_time *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_show_vpe_system_time_reply *reply),
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
  vapi_msg_show_vpe_system_time_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_show_vpe_system_time_reply, VAPI_REQUEST_REG, 
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
    vapi_msg_show_vpe_system_time_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_show_vpe_system_time()
{
  static const char name[] = "show_vpe_system_time";
  static const char name_with_crc[] = "show_vpe_system_time_51077d14";
  static vapi_message_desc_t __vapi_metadata_show_vpe_system_time = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_show_vpe_system_time_msg_size,
    (generic_swap_fn_t)vapi_msg_show_vpe_system_time_hton,
    (generic_swap_fn_t)vapi_msg_show_vpe_system_time_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_show_vpe_system_time = vapi_register_msg(&__vapi_metadata_show_vpe_system_time);
  VAPI_DBG("Assigned msg id %d to show_vpe_system_time", vapi_msg_id_show_vpe_system_time);
}
#endif

#ifndef defined_vapi_msg_log_details
#define defined_vapi_msg_log_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_timestamp timestamp;
  vapi_enum_log_level level;
  u8 msg_class[32];
  u8 message[256]; 
} vapi_payload_log_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_log_details payload;
} vapi_msg_log_details;

static inline void vapi_msg_log_details_payload_hton(vapi_payload_log_details *payload)
{
  payload->level = (vapi_enum_log_level)htobe32(payload->level);
}

static inline void vapi_msg_log_details_payload_ntoh(vapi_payload_log_details *payload)
{
  payload->level = (vapi_enum_log_level)be32toh(payload->level);
}

static inline void vapi_msg_log_details_hton(vapi_msg_log_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_log_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_log_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_log_details_ntoh(vapi_msg_log_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_log_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_log_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_log_details_msg_size(vapi_msg_log_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_log_details_msg_size(vapi_msg_log_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_log_details) > buf_size)
    {
      VAPI_ERR("Truncated 'log_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_log_details));
      return -1;
    }
  if (vapi_calc_log_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'log_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_log_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_log_details()
{
  static const char name[] = "log_details";
  static const char name_with_crc[] = "log_details_03d61cc0";
  static vapi_message_desc_t __vapi_metadata_log_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_log_details, payload),
    (verify_msg_size_fn_t)vapi_verify_log_details_msg_size,
    (generic_swap_fn_t)vapi_msg_log_details_hton,
    (generic_swap_fn_t)vapi_msg_log_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_log_details = vapi_register_msg(&__vapi_metadata_log_details);
  VAPI_DBG("Assigned msg id %d to log_details", vapi_msg_id_log_details);
}

static inline void vapi_set_vapi_msg_log_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_log_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_log_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_log_dump
#define defined_vapi_msg_log_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_timestamp start_timestamp; 
} vapi_payload_log_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_log_dump payload;
} vapi_msg_log_dump;

static inline void vapi_msg_log_dump_payload_hton(vapi_payload_log_dump *payload)
{

}

static inline void vapi_msg_log_dump_payload_ntoh(vapi_payload_log_dump *payload)
{

}

static inline void vapi_msg_log_dump_hton(vapi_msg_log_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_log_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_log_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_log_dump_ntoh(vapi_msg_log_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_log_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_log_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_log_dump_msg_size(vapi_msg_log_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_log_dump_msg_size(vapi_msg_log_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_log_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'log_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_log_dump));
      return -1;
    }
  if (vapi_calc_log_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'log_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_log_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_log_dump* vapi_alloc_log_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_log_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_log_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_log_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_log_dump);

  return msg;
}

static inline vapi_error_e vapi_log_dump(struct vapi_ctx_s *ctx,
  vapi_msg_log_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_log_details *reply),
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
  vapi_msg_log_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_log_details, VAPI_REQUEST_DUMP, 
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
    vapi_msg_log_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_log_dump()
{
  static const char name[] = "log_dump";
  static const char name_with_crc[] = "log_dump_6ab31753";
  static vapi_message_desc_t __vapi_metadata_log_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_log_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_log_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_log_dump_hton,
    (generic_swap_fn_t)vapi_msg_log_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_log_dump = vapi_register_msg(&__vapi_metadata_log_dump);
  VAPI_DBG("Assigned msg id %d to log_dump", vapi_msg_id_log_dump);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
