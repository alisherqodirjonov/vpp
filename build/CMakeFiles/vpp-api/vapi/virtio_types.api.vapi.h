#ifndef __included_virtio_types_api_json
#define __included_virtio_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_VIRTIO_TYPES_API_JSON\



#ifndef defined_vapi_enum_virtio_net_features_first_32
#define defined_vapi_enum_virtio_net_features_first_32
typedef enum {
  VIRTIO_NET_F_API_CSUM = 1,
  VIRTIO_NET_F_API_GUEST_CSUM = 2,
  VIRTIO_NET_F_API_GUEST_TSO4 = 128,
  VIRTIO_NET_F_API_GUEST_TSO6 = 256,
  VIRTIO_NET_F_API_GUEST_UFO = 1024,
  VIRTIO_NET_F_API_HOST_TSO4 = 2048,
  VIRTIO_NET_F_API_HOST_TSO6 = 4096,
  VIRTIO_NET_F_API_HOST_UFO = 16384,
  VIRTIO_NET_F_API_MRG_RXBUF = 32768,
  VIRTIO_NET_F_API_CTRL_VQ = 131072,
  VIRTIO_NET_F_API_GUEST_ANNOUNCE = 2097152,
  VIRTIO_NET_F_API_MQ = 4194304,
  VHOST_F_API_LOG_ALL = 67108864,
  VIRTIO_F_API_ANY_LAYOUT = 134217728,
  VIRTIO_F_API_INDIRECT_DESC = 268435456,
  VHOST_USER_F_API_PROTOCOL_FEATURES = 1073741824,
}  vapi_enum_virtio_net_features_first_32;

#endif

#ifndef defined_vapi_enum_virtio_net_features_last_32
#define defined_vapi_enum_virtio_net_features_last_32
typedef enum {
  VIRTIO_F_API_VERSION_1 = 1,
}  vapi_enum_virtio_net_features_last_32;

#endif


#ifdef __cplusplus
}
#endif

#endif
