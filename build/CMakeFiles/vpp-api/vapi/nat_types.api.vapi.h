#ifndef __included_nat_types_api_json
#define __included_nat_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_NAT_TYPES_API_JSON\



#ifndef defined_vapi_enum_nat_log_level
#define defined_vapi_enum_nat_log_level
typedef enum {
  NAT_LOG_NONE = 0,
  NAT_LOG_ERROR = 1,
  NAT_LOG_WARNING = 2,
  NAT_LOG_NOTICE = 3,
  NAT_LOG_INFO = 4,
  NAT_LOG_DEBUG = 5,
} __attribute__((packed)) vapi_enum_nat_log_level;

#endif

#ifndef defined_vapi_enum_nat_config_flags
#define defined_vapi_enum_nat_config_flags
typedef enum {
  NAT_IS_NONE = 0,
  NAT_IS_TWICE_NAT = 1,
  NAT_IS_SELF_TWICE_NAT = 2,
  NAT_IS_OUT2IN_ONLY = 4,
  NAT_IS_ADDR_ONLY = 8,
  NAT_IS_OUTSIDE = 16,
  NAT_IS_INSIDE = 32,
  NAT_IS_STATIC = 64,
  NAT_IS_EXT_HOST_VALID = 128,
} __attribute__((packed)) vapi_enum_nat_config_flags;

#endif

#ifndef defined_vapi_type_nat_timeouts
#define defined_vapi_type_nat_timeouts
typedef struct __attribute__((__packed__)) {
  u32 udp;
  u32 tcp_established;
  u32 tcp_transitory;
  u32 icmp;
} vapi_type_nat_timeouts;

static inline void vapi_type_nat_timeouts_hton(vapi_type_nat_timeouts *msg)
{
  msg->udp = htobe32(msg->udp);
  msg->tcp_established = htobe32(msg->tcp_established);
  msg->tcp_transitory = htobe32(msg->tcp_transitory);
  msg->icmp = htobe32(msg->icmp);
}

static inline void vapi_type_nat_timeouts_ntoh(vapi_type_nat_timeouts *msg)
{
  msg->udp = be32toh(msg->udp);
  msg->tcp_established = be32toh(msg->tcp_established);
  msg->tcp_transitory = be32toh(msg->tcp_transitory);
  msg->icmp = be32toh(msg->icmp);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
