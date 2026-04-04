#ifndef __included_policer_types_api_json
#define __included_policer_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_POLICER_TYPES_API_JSON\



#ifndef defined_vapi_enum_sse2_qos_rate_type
#define defined_vapi_enum_sse2_qos_rate_type
typedef enum {
  SSE2_QOS_RATE_API_KBPS = 0,
  SSE2_QOS_RATE_API_PPS = 1,
  SSE2_QOS_RATE_API_INVALID = 2,
} __attribute__((packed)) vapi_enum_sse2_qos_rate_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_round_type
#define defined_vapi_enum_sse2_qos_round_type
typedef enum {
  SSE2_QOS_ROUND_API_TO_CLOSEST = 0,
  SSE2_QOS_ROUND_API_TO_UP = 1,
  SSE2_QOS_ROUND_API_TO_DOWN = 2,
  SSE2_QOS_ROUND_API_INVALID = 3,
} __attribute__((packed)) vapi_enum_sse2_qos_round_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_policer_type
#define defined_vapi_enum_sse2_qos_policer_type
typedef enum {
  SSE2_QOS_POLICER_TYPE_API_1R2C = 0,
  SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697 = 1,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698 = 2,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115 = 3,
  SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1 = 4,
  SSE2_QOS_POLICER_TYPE_API_MAX = 5,
} __attribute__((packed)) vapi_enum_sse2_qos_policer_type;

#endif

#ifndef defined_vapi_enum_sse2_qos_action_type
#define defined_vapi_enum_sse2_qos_action_type
typedef enum {
  SSE2_QOS_ACTION_API_DROP = 0,
  SSE2_QOS_ACTION_API_TRANSMIT = 1,
  SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT = 2,
} __attribute__((packed)) vapi_enum_sse2_qos_action_type;

#endif

#ifndef defined_vapi_type_sse2_qos_action
#define defined_vapi_type_sse2_qos_action
typedef struct __attribute__((__packed__)) {
  vapi_enum_sse2_qos_action_type type;
  u8 dscp;
} vapi_type_sse2_qos_action;

static inline void vapi_type_sse2_qos_action_hton(vapi_type_sse2_qos_action *msg)
{

}

static inline void vapi_type_sse2_qos_action_ntoh(vapi_type_sse2_qos_action *msg)
{

}
#endif

#ifndef defined_vapi_type_policer_config
#define defined_vapi_type_policer_config
typedef struct __attribute__((__packed__)) {
  u32 cir;
  u32 eir;
  u64 cb;
  u64 eb;
  vapi_enum_sse2_qos_rate_type rate_type;
  vapi_enum_sse2_qos_round_type round_type;
  vapi_enum_sse2_qos_policer_type type;
  bool color_aware;
  vapi_type_sse2_qos_action conform_action;
  vapi_type_sse2_qos_action exceed_action;
  vapi_type_sse2_qos_action violate_action;
} vapi_type_policer_config;

static inline void vapi_type_policer_config_hton(vapi_type_policer_config *msg)
{
  msg->cir = htobe32(msg->cir);
  msg->eir = htobe32(msg->eir);
  msg->cb = htobe64(msg->cb);
  msg->eb = htobe64(msg->eb);
}

static inline void vapi_type_policer_config_ntoh(vapi_type_policer_config *msg)
{
  msg->cir = be32toh(msg->cir);
  msg->eir = be32toh(msg->eir);
  msg->cb = be64toh(msg->cb);
  msg->eb = be64toh(msg->eb);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
