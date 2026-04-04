#ifndef included_mss_clamp_api_types_h
#define included_mss_clamp_api_types_h
#define VL_API_MSS_CLAMP_API_VERSION_MAJOR 1
#define VL_API_MSS_CLAMP_API_VERSION_MINOR 0
#define VL_API_MSS_CLAMP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    MSS_CLAMP_DIR_NONE = 0,
    MSS_CLAMP_DIR_RX = 1,
    MSS_CLAMP_DIR_TX = 2,
} vl_api_mss_clamp_dir_t;
STATIC_ASSERT(sizeof(vl_api_mss_clamp_dir_t) == sizeof(u8), "size of API enum mss_clamp_dir is wrong");
typedef struct __attribute__ ((packed)) _vl_api_mss_clamp_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u16 ipv4_mss;
    u16 ipv6_mss;
    vl_api_mss_clamp_dir_t ipv4_direction;
    vl_api_mss_clamp_dir_t ipv6_direction;
} vl_api_mss_clamp_enable_disable_t;
#define VL_API_MSS_CLAMP_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mss_clamp_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mss_clamp_enable_disable_reply_t;
#define VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mss_clamp_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    vl_api_interface_index_t sw_if_index;
} vl_api_mss_clamp_get_t;
#define VL_API_MSS_CLAMP_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mss_clamp_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_mss_clamp_get_reply_t;
#define VL_API_MSS_CLAMP_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mss_clamp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u16 ipv4_mss;
    u16 ipv6_mss;
    vl_api_mss_clamp_dir_t ipv4_direction;
    vl_api_mss_clamp_dir_t ipv6_direction;
} vl_api_mss_clamp_details_t;
#define VL_API_MSS_CLAMP_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_MSS_CLAMP_ENABLE_DISABLE_CRC "mss_clamp_enable_disable_d31b44e3"
#define VL_API_MSS_CLAMP_ENABLE_DISABLE_REPLY_CRC "mss_clamp_enable_disable_reply_e8d4e804"
#define VL_API_MSS_CLAMP_GET_CRC "mss_clamp_get_47250981"
#define VL_API_MSS_CLAMP_GET_REPLY_CRC "mss_clamp_get_reply_53b48f5d"
#define VL_API_MSS_CLAMP_DETAILS_CRC "mss_clamp_details_d3a4de61"

#endif
