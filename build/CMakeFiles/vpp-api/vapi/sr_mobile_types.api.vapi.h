#ifndef __included_sr_mobile_types_api_json
#define __included_sr_mobile_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_SR_MOBILE_TYPES_API_JSON\



#ifndef defined_vapi_enum_sr_mobile_nhtype
#define defined_vapi_enum_sr_mobile_nhtype
typedef enum {
  SRV6_NHTYPE_API_NONE = 0,
  SRV6_NHTYPE_API_IPV4 = 1,
  SRV6_NHTYPE_API_IPV6 = 2,
  SRV6_NHTYPE_API_NON_IP = 3,
} __attribute__((packed)) vapi_enum_sr_mobile_nhtype;

#endif


#ifdef __cplusplus
}
#endif

#endif
