#ifndef included_vmxnet3_api_types_h
#define included_vmxnet3_api_types_h
#define VL_API_VMXNET3_API_VERSION_MAJOR 1
#define VL_API_VMXNET3_API_VERSION_MINOR 2
#define VL_API_VMXNET3_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_tx_list {
    u16 tx_qsize;
    u16 tx_next;
    u16 tx_produce;
    u16 tx_consume;
} vl_api_vmxnet3_tx_list_t;
#define VL_API_VMXNET3_TX_LIST_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_rx_list {
    u16 rx_qsize;
    u16 rx_fill[2];
    u16 rx_next;
    u16 rx_produce[2];
    u16 rx_consume[2];
} vl_api_vmxnet3_rx_list_t;
#define VL_API_VMXNET3_RX_LIST_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 pci_addr;
    i32 enable_elog;
    u16 rxq_size;
    u16 rxq_num;
    u16 txq_size;
    u16 txq_num;
    u8 bind;
    bool enable_gso;
} vl_api_vmxnet3_create_t;
#define VL_API_VMXNET3_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_vmxnet3_create_reply_t;
#define VL_API_VMXNET3_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_vmxnet3_delete_t;
#define VL_API_VMXNET3_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vmxnet3_delete_reply_t;
#define VL_API_VMXNET3_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 if_name[64];
    vl_api_mac_address_t hw_addr;
    u32 pci_addr;
    u8 version;
    bool admin_up_down;
    u8 rx_count;
    vl_api_vmxnet3_rx_list_t rx_list[16];
    u8 tx_count;
    vl_api_vmxnet3_tx_list_t tx_list[8];
} vl_api_vmxnet3_details_t;
#define VL_API_VMXNET3_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vmxnet3_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_vmxnet3_dump_t;
#define VL_API_VMXNET3_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_vmxnet3_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sw_vmxnet3_interface_dump_t;
#define VL_API_SW_VMXNET3_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_vmxnet3_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 if_name[64];
    vl_api_mac_address_t hw_addr;
    u32 pci_addr;
    u8 version;
    bool admin_up_down;
    u8 rx_count;
    vl_api_vmxnet3_rx_list_t rx_list[16];
    u8 tx_count;
    vl_api_vmxnet3_tx_list_t tx_list[8];
} vl_api_sw_vmxnet3_interface_details_t;
#define VL_API_SW_VMXNET3_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_VMXNET3_CREATE_CRC "vmxnet3_create_71a07314"
#define VL_API_VMXNET3_CREATE_REPLY_CRC "vmxnet3_create_reply_5383d31f"
#define VL_API_VMXNET3_DELETE_CRC "vmxnet3_delete_f9e6675e"
#define VL_API_VMXNET3_DELETE_REPLY_CRC "vmxnet3_delete_reply_e8d4e804"
#define VL_API_VMXNET3_DETAILS_CRC "vmxnet3_details_6a1a5498"
#define VL_API_VMXNET3_DUMP_CRC "vmxnet3_dump_51077d14"
#define VL_API_SW_VMXNET3_INTERFACE_DUMP_CRC "sw_vmxnet3_interface_dump_f9e6675e"
#define VL_API_SW_VMXNET3_INTERFACE_DETAILS_CRC "sw_vmxnet3_interface_details_6a1a5498"

#endif
