#ifndef included_idpf_api_types_h
#define included_idpf_api_types_h
#define VL_API_IDPF_API_VERSION_MAJOR 1
#define VL_API_IDPF_API_VERSION_MINOR 0
#define VL_API_IDPF_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_idpf_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 pci_addr;
    u16 rxq_single;
    u16 txq_single;
    u16 rxq_num;
    u16 txq_num;
    u16 rxq_size;
    u16 txq_size;
    u16 req_vport_nb;
} vl_api_idpf_create_t;
#define VL_API_IDPF_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_idpf_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_idpf_create_reply_t;
#define VL_API_IDPF_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_idpf_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_idpf_delete_t;
#define VL_API_IDPF_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_idpf_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_idpf_delete_reply_t;
#define VL_API_IDPF_DELETE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_IDPF_CREATE_CRC "idpf_create_2ba86d91"
#define VL_API_IDPF_CREATE_REPLY_CRC "idpf_create_reply_5383d31f"
#define VL_API_IDPF_DELETE_CRC "idpf_delete_f9e6675e"
#define VL_API_IDPF_DELETE_REPLY_CRC "idpf_delete_reply_e8d4e804"

#endif
