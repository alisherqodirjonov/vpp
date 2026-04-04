/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vlib/pci/pci_types.api_fromjson.h>
#ifndef included_virtio_api_fromjson_h
#define included_virtio_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_virtio_flags_t_fromjson (void **mp, int *len, cJSON *o, vl_api_virtio_flags_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "VIRTIO_API_FLAG_GSO") == 0) *a |= 1;
       if (strcmp(p, "VIRTIO_API_FLAG_CSUM_OFFLOAD") == 0) *a |= 2;
       if (strcmp(p, "VIRTIO_API_FLAG_GRO_COALESCE") == 0) *a |= 4;
       if (strcmp(p, "VIRTIO_API_FLAG_PACKED") == 0) *a |= 8;
       if (strcmp(p, "VIRTIO_API_FLAG_IN_ORDER") == 0) *a |= 16;
       if (strcmp(p, "VIRTIO_API_FLAG_BUFFERING") == 0) *a |= 32;
       if (strcmp(p, "VIRTIO_API_FLAG_RSS") == 0) *a |= 64;
    }
   return 0;
}
static inline vl_api_virtio_pci_create_t *vl_api_virtio_pci_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_create_t);
    vl_api_virtio_pci_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    if (vl_api_pci_address_t_fromjson((void **)&a, &l, item, &a->pci_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_random_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gso_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->gso_enabled);

    item = cJSON_GetObjectItem(o, "checksum_offload_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->checksum_offload_enabled);

    item = cJSON_GetObjectItem(o, "features");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->features);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_virtio_pci_create_reply_t *vl_api_virtio_pci_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_create_reply_t);
    vl_api_virtio_pci_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_virtio_pci_create_v2_t *vl_api_virtio_pci_create_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_create_v2_t);
    vl_api_virtio_pci_create_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    if (vl_api_pci_address_t_fromjson((void **)&a, &l, item, &a->pci_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_random_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_random_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "virtio_flags");
    if (!item) goto error;
    if (vl_api_virtio_flags_t_fromjson((void **)&a, &l, item, &a->virtio_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "features");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->features);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_virtio_pci_create_v2_reply_t *vl_api_virtio_pci_create_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_create_v2_reply_t);
    vl_api_virtio_pci_create_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_virtio_pci_delete_t *vl_api_virtio_pci_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_delete_t);
    vl_api_virtio_pci_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_virtio_pci_delete_reply_t *vl_api_virtio_pci_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_virtio_pci_delete_reply_t);
    vl_api_virtio_pci_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_virtio_pci_dump_t *vl_api_sw_interface_virtio_pci_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_virtio_pci_dump_t);
    vl_api_sw_interface_virtio_pci_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_interface_virtio_pci_details_t *vl_api_sw_interface_virtio_pci_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_virtio_pci_details_t);
    vl_api_sw_interface_virtio_pci_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    if (vl_api_pci_address_t_fromjson((void **)&a, &l, item, &a->pci_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_ring_sz);

    item = cJSON_GetObjectItem(o, "rx_ring_sz");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_ring_sz);

    item = cJSON_GetObjectItem(o, "features");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->features);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
