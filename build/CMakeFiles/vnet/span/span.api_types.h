#ifndef included_span_api_types_h
#define included_span_api_types_h
#define VL_API_SPAN_API_VERSION_MAJOR 2
#define VL_API_SPAN_API_VERSION_MINOR 0
#define VL_API_SPAN_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef enum {
    SPAN_STATE_API_DISABLED = 0,
    SPAN_STATE_API_RX = 1,
    SPAN_STATE_API_TX = 2,
    SPAN_STATE_API_RX_TX = 3,
} vl_api_span_state_t;
typedef struct __attribute__ ((packed)) _vl_api_sw_interface_span_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index_from;
    vl_api_interface_index_t sw_if_index_to;
    vl_api_span_state_t state;
    bool is_l2;
} vl_api_sw_interface_span_enable_disable_t;
#define VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_span_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_span_enable_disable_reply_t;
#define VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_span_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_l2;
} vl_api_sw_interface_span_dump_t;
#define VL_API_SW_INTERFACE_SPAN_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_span_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index_from;
    vl_api_interface_index_t sw_if_index_to;
    vl_api_span_state_t state;
    bool is_l2;
} vl_api_sw_interface_span_details_t;
#define VL_API_SW_INTERFACE_SPAN_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_CRC "sw_interface_span_enable_disable_23ddd96b"
#define VL_API_SW_INTERFACE_SPAN_ENABLE_DISABLE_REPLY_CRC "sw_interface_span_enable_disable_reply_e8d4e804"
#define VL_API_SW_INTERFACE_SPAN_DUMP_CRC "sw_interface_span_dump_d6cf0c3d"
#define VL_API_SW_INTERFACE_SPAN_DETAILS_CRC "sw_interface_span_details_8a20e79f"

#endif
