#ifndef included_svs_api_types_h
#define included_svs_api_types_h
#define VL_API_SVS_API_VERSION_MAJOR 1
#define VL_API_SVS_API_VERSION_MINOR 0
#define VL_API_SVS_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_svs_plugin_get_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_svs_plugin_get_version_t;
#define VL_API_SVS_PLUGIN_GET_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_plugin_get_version_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 major;
    u32 minor;
} vl_api_svs_plugin_get_version_reply_t;
#define VL_API_SVS_PLUGIN_GET_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_table_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_family_t af;
    u32 table_id;
} vl_api_svs_table_add_del_t;
#define VL_API_SVS_TABLE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_table_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_svs_table_add_del_reply_t;
#define VL_API_SVS_TABLE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_route_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_prefix_t prefix;
    u32 table_id;
    u32 source_table_id;
} vl_api_svs_route_add_del_t;
#define VL_API_SVS_ROUTE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_route_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_svs_route_add_del_reply_t;
#define VL_API_SVS_ROUTE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
    vl_api_address_family_t af;
    u32 table_id;
    vl_api_interface_index_t sw_if_index;
} vl_api_svs_enable_disable_t;
#define VL_API_SVS_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_svs_enable_disable_reply_t;
#define VL_API_SVS_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_svs_dump_t;
#define VL_API_SVS_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_svs_details {
    u16 _vl_msg_id;
    u32 context;
    u32 table_id;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_family_t af;
} vl_api_svs_details_t;
#define VL_API_SVS_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SVS_PLUGIN_GET_VERSION_CRC "svs_plugin_get_version_51077d14"
#define VL_API_SVS_PLUGIN_GET_VERSION_REPLY_CRC "svs_plugin_get_version_reply_9b32cf86"
#define VL_API_SVS_TABLE_ADD_DEL_CRC "svs_table_add_del_7d21cb2a"
#define VL_API_SVS_TABLE_ADD_DEL_REPLY_CRC "svs_table_add_del_reply_e8d4e804"
#define VL_API_SVS_ROUTE_ADD_DEL_CRC "svs_route_add_del_e49bc63c"
#define VL_API_SVS_ROUTE_ADD_DEL_REPLY_CRC "svs_route_add_del_reply_e8d4e804"
#define VL_API_SVS_ENABLE_DISABLE_CRC "svs_enable_disable_634b89d2"
#define VL_API_SVS_ENABLE_DISABLE_REPLY_CRC "svs_enable_disable_reply_e8d4e804"
#define VL_API_SVS_DUMP_CRC "svs_dump_51077d14"
#define VL_API_SVS_DETAILS_CRC "svs_details_6282cd55"

#endif
