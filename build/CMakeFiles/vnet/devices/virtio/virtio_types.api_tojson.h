/* Imported API files */
#ifndef included_virtio_types_api_tojson_h
#define included_virtio_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_virtio_net_features_first_32_t_tojson (vl_api_virtio_net_features_first_32_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("VIRTIO_NET_F_API_CSUM");
    case 2:
        return cJSON_CreateString("VIRTIO_NET_F_API_GUEST_CSUM");
    case 128:
        return cJSON_CreateString("VIRTIO_NET_F_API_GUEST_TSO4");
    case 256:
        return cJSON_CreateString("VIRTIO_NET_F_API_GUEST_TSO6");
    case 1024:
        return cJSON_CreateString("VIRTIO_NET_F_API_GUEST_UFO");
    case 2048:
        return cJSON_CreateString("VIRTIO_NET_F_API_HOST_TSO4");
    case 4096:
        return cJSON_CreateString("VIRTIO_NET_F_API_HOST_TSO6");
    case 16384:
        return cJSON_CreateString("VIRTIO_NET_F_API_HOST_UFO");
    case 32768:
        return cJSON_CreateString("VIRTIO_NET_F_API_MRG_RXBUF");
    case 131072:
        return cJSON_CreateString("VIRTIO_NET_F_API_CTRL_VQ");
    case 2097152:
        return cJSON_CreateString("VIRTIO_NET_F_API_GUEST_ANNOUNCE");
    case 4194304:
        return cJSON_CreateString("VIRTIO_NET_F_API_MQ");
    case 67108864:
        return cJSON_CreateString("VHOST_F_API_LOG_ALL");
    case 134217728:
        return cJSON_CreateString("VIRTIO_F_API_ANY_LAYOUT");
    case 268435456:
        return cJSON_CreateString("VIRTIO_F_API_INDIRECT_DESC");
    case 1073741824:
        return cJSON_CreateString("VHOST_USER_F_API_PROTOCOL_FEATURES");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_virtio_net_features_last_32_t_tojson (vl_api_virtio_net_features_last_32_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("VIRTIO_F_API_VERSION_1");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
