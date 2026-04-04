#ifndef included_flow_api_types_h
#define included_flow_api_types_h
#define VL_API_FLOW_API_VERSION_MAJOR 1
#define VL_API_FLOW_API_VERSION_MINOR 0
#define VL_API_FLOW_API_VERSION_PATCH 3
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/flow/flow_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_flow_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_flow_rule_t flow;
} vl_api_flow_add_t;
#define VL_API_FLOW_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_add_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_flow_rule_v2_t flow;
} vl_api_flow_add_v2_t;
#define VL_API_FLOW_ADD_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 flow_index;
} vl_api_flow_add_reply_t;
#define VL_API_FLOW_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_add_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 flow_index;
} vl_api_flow_add_v2_reply_t;
#define VL_API_FLOW_ADD_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 flow_index;
} vl_api_flow_del_t;
#define VL_API_FLOW_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_flow_del_reply_t;
#define VL_API_FLOW_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 flow_index;
    u32 hw_if_index;
} vl_api_flow_enable_t;
#define VL_API_FLOW_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_flow_enable_reply_t;
#define VL_API_FLOW_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 flow_index;
    u32 hw_if_index;
} vl_api_flow_disable_t;
#define VL_API_FLOW_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_flow_disable_reply_t;
#define VL_API_FLOW_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_FLOW_ADD_CRC "flow_add_f946ed84"
#define VL_API_FLOW_ADD_V2_CRC "flow_add_v2_5b757558"
#define VL_API_FLOW_ADD_REPLY_CRC "flow_add_reply_8587dc85"
#define VL_API_FLOW_ADD_V2_REPLY_CRC "flow_add_v2_reply_8587dc85"
#define VL_API_FLOW_DEL_CRC "flow_del_b6b9b02c"
#define VL_API_FLOW_DEL_REPLY_CRC "flow_del_reply_e8d4e804"
#define VL_API_FLOW_ENABLE_CRC "flow_enable_2024be69"
#define VL_API_FLOW_ENABLE_REPLY_CRC "flow_enable_reply_e8d4e804"
#define VL_API_FLOW_DISABLE_CRC "flow_disable_2024be69"
#define VL_API_FLOW_DISABLE_REPLY_CRC "flow_disable_reply_e8d4e804"

#endif
