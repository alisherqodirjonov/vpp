#ifndef included_virtio_api_types_h
#define included_virtio_api_types_h
#define VL_API_VIRTIO_API_VERSION_MAJOR 3
#define VL_API_VIRTIO_API_VERSION_MINOR 0
#define VL_API_VIRTIO_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vlib/pci/pci_types.api_types.h>
typedef enum {
    VIRTIO_API_FLAG_GSO = 1,
    VIRTIO_API_FLAG_CSUM_OFFLOAD = 2,
    VIRTIO_API_FLAG_GRO_COALESCE = 4,
    VIRTIO_API_FLAG_PACKED = 8,
    VIRTIO_API_FLAG_IN_ORDER = 16,
    VIRTIO_API_FLAG_BUFFERING = 32,
    VIRTIO_API_FLAG_RSS = 64,
} vl_api_virtio_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_pci_address_t pci_addr;
    bool use_random_mac;
    vl_api_mac_address_t mac_address;
    bool gso_enabled;
    bool checksum_offload_enabled;
    u64 features;
} vl_api_virtio_pci_create_t;
#define VL_API_VIRTIO_PCI_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_virtio_pci_create_reply_t;
#define VL_API_VIRTIO_PCI_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_create_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_pci_address_t pci_addr;
    bool use_random_mac;
    vl_api_mac_address_t mac_address;
    vl_api_virtio_flags_t virtio_flags;
    u64 features;
} vl_api_virtio_pci_create_v2_t;
#define VL_API_VIRTIO_PCI_CREATE_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_create_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_virtio_pci_create_v2_reply_t;
#define VL_API_VIRTIO_PCI_CREATE_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_virtio_pci_delete_t;
#define VL_API_VIRTIO_PCI_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_virtio_pci_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_virtio_pci_delete_reply_t;
#define VL_API_VIRTIO_PCI_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_virtio_pci_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sw_interface_virtio_pci_dump_t;
#define VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_virtio_pci_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_pci_address_t pci_addr;
    vl_api_mac_address_t mac_addr;
    u16 tx_ring_sz;
    u16 rx_ring_sz;
    u64 features;
} vl_api_sw_interface_virtio_pci_details_t;
#define VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_VIRTIO_PCI_CREATE_CRC "virtio_pci_create_1944f8db"
#define VL_API_VIRTIO_PCI_CREATE_REPLY_CRC "virtio_pci_create_reply_5383d31f"
#define VL_API_VIRTIO_PCI_CREATE_V2_CRC "virtio_pci_create_v2_5d096e1a"
#define VL_API_VIRTIO_PCI_CREATE_V2_REPLY_CRC "virtio_pci_create_v2_reply_5383d31f"
#define VL_API_VIRTIO_PCI_DELETE_CRC "virtio_pci_delete_f9e6675e"
#define VL_API_VIRTIO_PCI_DELETE_REPLY_CRC "virtio_pci_delete_reply_e8d4e804"
#define VL_API_SW_INTERFACE_VIRTIO_PCI_DUMP_CRC "sw_interface_virtio_pci_dump_51077d14"
#define VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS_CRC "sw_interface_virtio_pci_details_6ca9c167"

#endif
