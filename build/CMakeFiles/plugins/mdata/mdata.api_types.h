#ifndef included_mdata_api_types_h
#define included_mdata_api_types_h
#define VL_API_MDATA_API_VERSION_MAJOR 0
#define VL_API_MDATA_API_VERSION_MINOR 1
#define VL_API_MDATA_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_mdata_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_disable;
} vl_api_mdata_enable_disable_t;
#define VL_API_MDATA_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mdata_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mdata_enable_disable_reply_t;
#define VL_API_MDATA_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_MDATA_ENABLE_DISABLE_CRC "mdata_enable_disable_2e7b47df"
#define VL_API_MDATA_ENABLE_DISABLE_REPLY_CRC "mdata_enable_disable_reply_e8d4e804"

#endif
