#ifndef included_pvti_api_types_h
#define included_pvti_api_types_h
#define VL_API_PVTI_API_VERSION_MAJOR 0
#define VL_API_PVTI_API_VERSION_MINOR 0
#define VL_API_PVTI_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_pvti_tunnel {
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t local_ip;
    u16 local_port;
    vl_api_address_t remote_ip;
    bool peer_address_from_payload;
    u16 remote_port;
    u16 underlay_mtu;
    u32 underlay_fib_index;
} vl_api_pvti_tunnel_t;
#define VL_API_PVTI_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_pvti_tunnel_t interface;
} vl_api_pvti_interface_create_t;
#define VL_API_PVTI_INTERFACE_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_pvti_interface_create_reply_t;
#define VL_API_PVTI_INTERFACE_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_pvti_interface_delete_t;
#define VL_API_PVTI_INTERFACE_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pvti_interface_delete_reply_t;
#define VL_API_PVTI_INTERFACE_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_pvti_interface_dump_t;
#define VL_API_PVTI_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pvti_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_pvti_tunnel_t interface;
} vl_api_pvti_interface_details_t;
#define VL_API_PVTI_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_PVTI_INTERFACE_CREATE_CRC "pvti_interface_create_a1e95595"
#define VL_API_PVTI_INTERFACE_CREATE_REPLY_CRC "pvti_interface_create_reply_5383d31f"
#define VL_API_PVTI_INTERFACE_DELETE_CRC "pvti_interface_delete_f9e6675e"
#define VL_API_PVTI_INTERFACE_DELETE_REPLY_CRC "pvti_interface_delete_reply_e8d4e804"
#define VL_API_PVTI_INTERFACE_DUMP_CRC "pvti_interface_dump_f9e6675e"
#define VL_API_PVTI_INTERFACE_DETAILS_CRC "pvti_interface_details_a26072b7"

#endif
