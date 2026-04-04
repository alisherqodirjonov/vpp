#ifndef __included_vpe_types_api_json
#define __included_vpe_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_VPE_TYPES_API_JSON\



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


#ifdef __cplusplus
}
#endif

#endif
