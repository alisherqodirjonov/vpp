#ifndef included_l3xc_api_types_h
#define included_l3xc_api_types_h
#define VL_API_L3XC_API_VERSION_MAJOR 1
#define VL_API_L3XC_API_VERSION_MINOR 0
#define VL_API_L3XC_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_l3xc {
    vl_api_interface_index_t sw_if_index;
    bool is_ip6;
    u8 n_paths;
    vl_api_fib_path_t paths[0];
} vl_api_l3xc_t;
#define VL_API_L3XC_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_plugin_get_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_l3xc_plugin_get_version_t;
#define VL_API_L3XC_PLUGIN_GET_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_plugin_get_version_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 major;
    u32 minor;
} vl_api_l3xc_plugin_get_version_reply_t;
#define VL_API_L3XC_PLUGIN_GET_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_l3xc_t l3xc;
} vl_api_l3xc_update_t;
#define VL_API_L3XC_UPDATE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stats_index;
} vl_api_l3xc_update_reply_t;
#define VL_API_L3XC_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_ip6;
} vl_api_l3xc_del_t;
#define VL_API_L3XC_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_l3xc_del_reply_t;
#define VL_API_L3XC_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_l3xc_dump_t;
#define VL_API_L3XC_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l3xc_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_l3xc_t l3xc;
} vl_api_l3xc_details_t;
#define VL_API_L3XC_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_L3XC_PLUGIN_GET_VERSION_CRC "l3xc_plugin_get_version_51077d14"
#define VL_API_L3XC_PLUGIN_GET_VERSION_REPLY_CRC "l3xc_plugin_get_version_reply_9b32cf86"
#define VL_API_L3XC_UPDATE_CRC "l3xc_update_e96aabdf"
#define VL_API_L3XC_UPDATE_REPLY_CRC "l3xc_update_reply_1992deab"
#define VL_API_L3XC_DEL_CRC "l3xc_del_e7dbef91"
#define VL_API_L3XC_DEL_REPLY_CRC "l3xc_del_reply_e8d4e804"
#define VL_API_L3XC_DUMP_CRC "l3xc_dump_f9e6675e"
#define VL_API_L3XC_DETAILS_CRC "l3xc_details_bc5bf852"

#endif
