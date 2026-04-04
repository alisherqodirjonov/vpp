#ifndef included_urpf_api_types_h
#define included_urpf_api_types_h
#define VL_API_URPF_API_VERSION_MAJOR 1
#define VL_API_URPF_API_VERSION_MINOR 0
#define VL_API_URPF_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    URPF_API_MODE_OFF = 0,
    URPF_API_MODE_LOOSE = 1,
    URPF_API_MODE_STRICT = 2,
} vl_api_urpf_mode_t;
STATIC_ASSERT(sizeof(vl_api_urpf_mode_t) == sizeof(u8), "size of API enum urpf_mode is wrong");
typedef struct __attribute__ ((packed)) _vl_api_urpf_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_input;
    vl_api_urpf_mode_t mode;
    vl_api_address_family_t af;
    vl_api_interface_index_t sw_if_index;
} vl_api_urpf_update_t;
#define VL_API_URPF_UPDATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_urpf_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_urpf_update_reply_t;
#define VL_API_URPF_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_urpf_update_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_input;
    vl_api_urpf_mode_t mode;
    vl_api_address_family_t af;
    vl_api_interface_index_t sw_if_index;
    u32 table_id;
} vl_api_urpf_update_v2_t;
#define VL_API_URPF_UPDATE_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_urpf_update_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_urpf_update_v2_reply_t;
#define VL_API_URPF_UPDATE_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_urpf_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_urpf_interface_dump_t;
#define VL_API_URPF_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_urpf_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_input;
    vl_api_urpf_mode_t mode;
    vl_api_address_family_t af;
    u32 table_id;
} vl_api_urpf_interface_details_t;
#define VL_API_URPF_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_URPF_UPDATE_CRC "urpf_update_cc274cd1"
#define VL_API_URPF_UPDATE_REPLY_CRC "urpf_update_reply_e8d4e804"
#define VL_API_URPF_UPDATE_V2_CRC "urpf_update_v2_b873d028"
#define VL_API_URPF_UPDATE_V2_REPLY_CRC "urpf_update_v2_reply_e8d4e804"
#define VL_API_URPF_INTERFACE_DUMP_CRC "urpf_interface_dump_f9e6675e"
#define VL_API_URPF_INTERFACE_DETAILS_CRC "urpf_interface_details_f94b5374"

#endif
