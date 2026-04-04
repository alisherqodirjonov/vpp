#ifndef included_tracedump_api_types_h
#define included_tracedump_api_types_h
#define VL_API_TRACEDUMP_API_VERSION_MAJOR 0
#define VL_API_TRACEDUMP_API_VERSION_MINOR 2
#define VL_API_TRACEDUMP_API_VERSION_PATCH 0
/* Imported API files */
typedef enum {
    TRACE_FF_NONE = 0,
    TRACE_FF_INCLUDE_NODE = 1,
    TRACE_FF_EXCLUDE_NODE = 2,
    TRACE_FF_INCLUDE_CLASSIFIER = 3,
    TRACE_FF_EXCLUDE_CLASSIFIER = 4,
} vl_api_trace_filter_flag_t;
typedef struct __attribute__ ((packed)) _vl_api_trace_set_filters {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_trace_filter_flag_t flag;
    u32 count;
    u32 node_index;
    u32 classifier_table_index;
} vl_api_trace_set_filters_t;
#define VL_API_TRACE_SET_FILTERS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_set_filters_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_set_filters_reply_t;
#define VL_API_TRACE_SET_FILTERS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_capture_packets {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 node_index;
    u32 max_packets;
    bool use_filter;
    bool verbose;
    bool pre_capture_clear;
} vl_api_trace_capture_packets_t;
#define VL_API_TRACE_CAPTURE_PACKETS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_capture_packets_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_capture_packets_reply_t;
#define VL_API_TRACE_CAPTURE_PACKETS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_clear_capture {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_trace_clear_capture_t;
#define VL_API_TRACE_CLEAR_CAPTURE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_clear_capture_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_clear_capture_reply_t;
#define VL_API_TRACE_CLEAR_CAPTURE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 clear_cache;
    u32 thread_id;
    u32 position;
    u32 max_records;
} vl_api_trace_dump_t;
#define VL_API_TRACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_dump_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 last_thread_id;
    u32 last_position;
    u8 more_this_thread;
    u8 more_threads;
    u8 flush_only;
    u8 done;
} vl_api_trace_dump_reply_t;
#define VL_API_TRACE_DUMP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_details {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 thread_id;
    u32 position;
    u8 more_this_thread;
    u8 more_threads;
    u8 done;
    u32 packet_number;
    vl_api_string_t trace_data;
} vl_api_trace_details_t;
#define VL_API_TRACE_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_trace_clear_cache {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_trace_clear_cache_t;
#define VL_API_TRACE_CLEAR_CACHE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_clear_cache_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_clear_cache_reply_t;
#define VL_API_TRACE_CLEAR_CACHE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_v2_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 thread_id;
    u32 position;
    u32 max;
    bool clear_cache;
} vl_api_trace_v2_dump_t;
#define VL_API_TRACE_V2_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_v2_details {
    u16 _vl_msg_id;
    u32 context;
    u32 thread_id;
    u32 position;
    bool more;
    vl_api_string_t trace_data;
} vl_api_trace_v2_details_t;
#define VL_API_TRACE_V2_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_trace_set_filter_function {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_string_t filter_function_name;
} vl_api_trace_set_filter_function_t;
#define VL_API_TRACE_SET_FILTER_FUNCTION_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_trace_set_filter_function_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_trace_set_filter_function_reply_t;
#define VL_API_TRACE_SET_FILTER_FUNCTION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_filter_function_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_trace_filter_function_dump_t;
#define VL_API_TRACE_FILTER_FUNCTION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_trace_filter_function_details {
    u16 _vl_msg_id;
    u32 context;
    bool selected;
    vl_api_string_t name;
} vl_api_trace_filter_function_details_t;
#define VL_API_TRACE_FILTER_FUNCTION_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_TRACE_SET_FILTERS_CRC "trace_set_filters_f522b44a"
#define VL_API_TRACE_SET_FILTERS_REPLY_CRC "trace_set_filters_reply_e8d4e804"
#define VL_API_TRACE_CAPTURE_PACKETS_CRC "trace_capture_packets_9e791a9b"
#define VL_API_TRACE_CAPTURE_PACKETS_REPLY_CRC "trace_capture_packets_reply_e8d4e804"
#define VL_API_TRACE_CLEAR_CAPTURE_CRC "trace_clear_capture_51077d14"
#define VL_API_TRACE_CLEAR_CAPTURE_REPLY_CRC "trace_clear_capture_reply_e8d4e804"
#define VL_API_TRACE_DUMP_CRC "trace_dump_c7d6681f"
#define VL_API_TRACE_DUMP_REPLY_CRC "trace_dump_reply_e0e87f9d"
#define VL_API_TRACE_DETAILS_CRC "trace_details_1553e9eb"
#define VL_API_TRACE_CLEAR_CACHE_CRC "trace_clear_cache_51077d14"
#define VL_API_TRACE_CLEAR_CACHE_REPLY_CRC "trace_clear_cache_reply_e8d4e804"
#define VL_API_TRACE_V2_DUMP_CRC "trace_v2_dump_83f88d8e"
#define VL_API_TRACE_V2_DETAILS_CRC "trace_v2_details_91f87d52"
#define VL_API_TRACE_SET_FILTER_FUNCTION_CRC "trace_set_filter_function_616abb92"
#define VL_API_TRACE_SET_FILTER_FUNCTION_REPLY_CRC "trace_set_filter_function_reply_e8d4e804"
#define VL_API_TRACE_FILTER_FUNCTION_DUMP_CRC "trace_filter_function_dump_51077d14"
#define VL_API_TRACE_FILTER_FUNCTION_DETAILS_CRC "trace_filter_function_details_28821359"

#endif
