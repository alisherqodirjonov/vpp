#ifndef included_trace_api_types_h
#define included_trace_api_types_h
#define VL_API_TRACE_API_VERSION_MAJOR 1
#define VL_API_TRACE_API_VERSION_MINOR 0
#define VL_API_TRACE_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_trace_profile_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 trace_type;
    u8 num_elts;
    u8 trace_tsp;
    u32 node_id;
    u32 app_data;
} vl_api_trace_profile_add_t;
#define VL_API_TRACE_PROFILE_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_profile_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_profile_add_reply_t;
#define VL_API_TRACE_PROFILE_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_profile_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_trace_profile_del_t;
#define VL_API_TRACE_PROFILE_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_profile_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_profile_del_reply_t;
#define VL_API_TRACE_PROFILE_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_profile_show_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_trace_profile_show_config_t;
#define VL_API_TRACE_PROFILE_SHOW_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_profile_show_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 trace_type;
    u8 num_elts;
    u8 trace_tsp;
    u32 node_id;
    u32 app_data;
} vl_api_trace_profile_show_config_reply_t;
#define VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_TRACE_PROFILE_ADD_CRC "trace_profile_add_de08aa6d"
#define VL_API_TRACE_PROFILE_ADD_REPLY_CRC "trace_profile_add_reply_e8d4e804"
#define VL_API_TRACE_PROFILE_DEL_CRC "trace_profile_del_51077d14"
#define VL_API_TRACE_PROFILE_DEL_REPLY_CRC "trace_profile_del_reply_e8d4e804"
#define VL_API_TRACE_PROFILE_SHOW_CONFIG_CRC "trace_profile_show_config_51077d14"
#define VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY_CRC "trace_profile_show_config_reply_0f1d374c"

#endif
