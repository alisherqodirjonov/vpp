/* Imported API files */
#ifndef included_virtio_types_api_fromjson_h
#define included_virtio_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_virtio_net_features_first_32_t_fromjson(void **mp, int *len, cJSON *o, vl_api_virtio_net_features_first_32_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VIRTIO_NET_F_API_CSUM") == 0) {*a = 1; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_GUEST_CSUM") == 0) {*a = 2; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_GUEST_TSO4") == 0) {*a = 128; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_GUEST_TSO6") == 0) {*a = 256; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_GUEST_UFO") == 0) {*a = 1024; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_HOST_TSO4") == 0) {*a = 2048; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_HOST_TSO6") == 0) {*a = 4096; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_HOST_UFO") == 0) {*a = 16384; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_MRG_RXBUF") == 0) {*a = 32768; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_CTRL_VQ") == 0) {*a = 131072; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_GUEST_ANNOUNCE") == 0) {*a = 2097152; return 0;}
    if (strcmp(p, "VIRTIO_NET_F_API_MQ") == 0) {*a = 4194304; return 0;}
    if (strcmp(p, "VHOST_F_API_LOG_ALL") == 0) {*a = 67108864; return 0;}
    if (strcmp(p, "VIRTIO_F_API_ANY_LAYOUT") == 0) {*a = 134217728; return 0;}
    if (strcmp(p, "VIRTIO_F_API_INDIRECT_DESC") == 0) {*a = 268435456; return 0;}
    if (strcmp(p, "VHOST_USER_F_API_PROTOCOL_FEATURES") == 0) {*a = 1073741824; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_virtio_net_features_last_32_t_fromjson(void **mp, int *len, cJSON *o, vl_api_virtio_net_features_last_32_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VIRTIO_F_API_VERSION_1") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
#endif
