#ifndef included_http_static_api_types_h
#define included_http_static_api_types_h
#define VL_API_HTTP_STATIC_API_VERSION_MAJOR 2
#define VL_API_HTTP_STATIC_API_VERSION_MINOR 5
#define VL_API_HTTP_STATIC_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_http_static_enable_v4 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 fifo_size;
    u32 cache_size_limit;
    u32 max_age;
    u32 keepalive_timeout;
    u64 max_body_size;
    u32 prealloc_fifos;
    u32 private_segment_size;
    u8 www_root[256];
    u8 uri[256];
} vl_api_http_static_enable_v4_t;
#define VL_API_HTTP_STATIC_ENABLE_V4_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_http_static_enable_v4_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_http_static_enable_v4_reply_t;
#define VL_API_HTTP_STATIC_ENABLE_V4_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_http_static_enable_v5 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 fifo_size;
    u32 cache_size_limit;
    u32 max_age;
    u32 keepalive_timeout;
    u64 max_body_size;
    u32 rx_buff_thresh;
    u32 prealloc_fifos;
    u32 private_segment_size;
    u8 www_root[256];
    u8 uri[256];
} vl_api_http_static_enable_v5_t;
#define VL_API_HTTP_STATIC_ENABLE_V5_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_http_static_enable_v5_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_http_static_enable_v5_reply_t;
#define VL_API_HTTP_STATIC_ENABLE_V5_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_HTTP_STATIC_ENABLE_V4_CRC "http_static_enable_v4_37540bfc"
#define VL_API_HTTP_STATIC_ENABLE_V4_REPLY_CRC "http_static_enable_v4_reply_e8d4e804"
#define VL_API_HTTP_STATIC_ENABLE_V5_CRC "http_static_enable_v5_8bf84069"
#define VL_API_HTTP_STATIC_ENABLE_V5_REPLY_CRC "http_static_enable_v5_reply_e8d4e804"

#endif
