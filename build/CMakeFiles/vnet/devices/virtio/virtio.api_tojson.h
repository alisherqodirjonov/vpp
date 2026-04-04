/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vlib/pci/pci_types.api_tojson.h>
#ifndef included_virtio_api_tojson_h
#define included_virtio_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_virtio_flags_t_tojson (vl_api_virtio_flags_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & VIRTIO_API_FLAG_GSO)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_GSO"));
    if (a & VIRTIO_API_FLAG_CSUM_OFFLOAD)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_CSUM_OFFLOAD"));
    if (a & VIRTIO_API_FLAG_GRO_COALESCE)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_GRO_COALESCE"));
    if (a & VIRTIO_API_FLAG_PACKED)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_PACKED"));
    if (a & VIRTIO_API_FLAG_IN_ORDER)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_IN_ORDER"));
    if (a & VIRTIO_API_FLAG_BUFFERING)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_BUFFERING"));
    if (a & VIRTIO_API_FLAG_RSS)
       cJSON_AddItemToArray(array, cJSON_CreateString("VIRTIO_API_FLAG_RSS"));
    return array;
}
static inline cJSON *vl_api_virtio_pci_create_t_tojson (vl_api_virtio_pci_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_create");
    cJSON_AddStringToObject(o, "_crc", "1944f8db");
    cJSON_AddItemToObject(o, "pci_addr", vl_api_pci_address_t_tojson(&a->pci_addr));
    cJSON_AddBoolToObject(o, "use_random_mac", a->use_random_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddBoolToObject(o, "gso_enabled", a->gso_enabled);
    cJSON_AddBoolToObject(o, "checksum_offload_enabled", a->checksum_offload_enabled);
    cJSON_AddNumberToObject(o, "features", a->features);
    return o;
}
static inline cJSON *vl_api_virtio_pci_create_reply_t_tojson (vl_api_virtio_pci_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_virtio_pci_create_v2_t_tojson (vl_api_virtio_pci_create_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_create_v2");
    cJSON_AddStringToObject(o, "_crc", "5d096e1a");
    cJSON_AddItemToObject(o, "pci_addr", vl_api_pci_address_t_tojson(&a->pci_addr));
    cJSON_AddBoolToObject(o, "use_random_mac", a->use_random_mac);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddItemToObject(o, "virtio_flags", vl_api_virtio_flags_t_tojson(a->virtio_flags));
    cJSON_AddNumberToObject(o, "features", a->features);
    return o;
}
static inline cJSON *vl_api_virtio_pci_create_v2_reply_t_tojson (vl_api_virtio_pci_create_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_create_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_virtio_pci_delete_t_tojson (vl_api_virtio_pci_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_virtio_pci_delete_reply_t_tojson (vl_api_virtio_pci_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "virtio_pci_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_virtio_pci_dump_t_tojson (vl_api_sw_interface_virtio_pci_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_virtio_pci_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_interface_virtio_pci_details_t_tojson (vl_api_sw_interface_virtio_pci_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_virtio_pci_details");
    cJSON_AddStringToObject(o, "_crc", "6ca9c167");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "pci_addr", vl_api_pci_address_t_tojson(&a->pci_addr));
    cJSON_AddItemToObject(o, "mac_addr", vl_api_mac_address_t_tojson(&a->mac_addr));
    cJSON_AddNumberToObject(o, "tx_ring_sz", a->tx_ring_sz);
    cJSON_AddNumberToObject(o, "rx_ring_sz", a->rx_ring_sz);
    cJSON_AddNumberToObject(o, "features", a->features);
    return o;
}
#endif
