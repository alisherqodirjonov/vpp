#ifndef included_feature_api_types_h
#define included_feature_api_types_h
#define VL_API_FEATURE_API_VERSION_MAJOR 1
#define VL_API_FEATURE_API_VERSION_MINOR 0
#define VL_API_FEATURE_API_VERSION_PATCH 2
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_feature_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable;
    u8 arc_name[64];
    u8 feature_name[64];
} vl_api_feature_enable_disable_t;
#define VL_API_FEATURE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_feature_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_feature_enable_disable_reply_t;
#define VL_API_FEATURE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_feature_is_enabled {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 arc_name[64];
    u8 feature_name[64];
    vl_api_interface_index_t sw_if_index;
} vl_api_feature_is_enabled_t;
#define VL_API_FEATURE_IS_ENABLED_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_feature_is_enabled_reply {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    i32 retval;
    bool is_enabled;
} vl_api_feature_is_enabled_reply_t;
#define VL_API_FEATURE_IS_ENABLED_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_FEATURE_ENABLE_DISABLE_CRC "feature_enable_disable_7531c862"
#define VL_API_FEATURE_ENABLE_DISABLE_REPLY_CRC "feature_enable_disable_reply_e8d4e804"
#define VL_API_FEATURE_IS_ENABLED_CRC "feature_is_enabled_55db09e2"
#define VL_API_FEATURE_IS_ENABLED_REPLY_CRC "feature_is_enabled_reply_03f284b5"

#endif
