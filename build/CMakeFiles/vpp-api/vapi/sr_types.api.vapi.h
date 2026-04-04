#ifndef __included_sr_types_api_json
#define __included_sr_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_SR_TYPES_API_JSON\



#ifndef defined_vapi_enum_sr_policy_op
#define defined_vapi_enum_sr_policy_op
typedef enum {
  SR_POLICY_OP_API_NONE = 0,
  SR_POLICY_OP_API_ADD = 1,
  SR_POLICY_OP_API_DEL = 2,
  SR_POLICY_OP_API_MOD = 3,
} __attribute__((packed)) vapi_enum_sr_policy_op;

#endif

#ifndef defined_vapi_enum_sr_behavior
#define defined_vapi_enum_sr_behavior
typedef enum {
  SR_BEHAVIOR_API_END = 1,
  SR_BEHAVIOR_API_X = 2,
  SR_BEHAVIOR_API_T = 3,
  SR_BEHAVIOR_API_D_FIRST = 4,
  SR_BEHAVIOR_API_DX2 = 5,
  SR_BEHAVIOR_API_DX6 = 6,
  SR_BEHAVIOR_API_DX4 = 7,
  SR_BEHAVIOR_API_DT6 = 8,
  SR_BEHAVIOR_API_DT4 = 9,
  SR_BEHAVIOR_API_LAST = 10,
  SR_BEHAVIOR_API_END_UN_PERF = 11,
  SR_BEHAVIOR_API_END_UN = 12,
  SR_BEHAVIOR_API_UA = 13,
} __attribute__((packed)) vapi_enum_sr_behavior;

#endif

#ifndef defined_vapi_enum_sr_steer
#define defined_vapi_enum_sr_steer
typedef enum {
  SR_STEER_API_L2 = 2,
  SR_STEER_API_IPV4 = 4,
  SR_STEER_API_IPV6 = 6,
} __attribute__((packed)) vapi_enum_sr_steer;

#endif


#ifdef __cplusplus
}
#endif

#endif
