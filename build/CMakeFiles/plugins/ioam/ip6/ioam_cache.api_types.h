#ifndef included_ioam_cache_api_types_h
#define included_ioam_cache_api_types_h
#define VL_API_IOAM_CACHE_API_VERSION_MAJOR 1
#define VL_API_IOAM_CACHE_API_VERSION_MINOR 0
#define VL_API_IOAM_CACHE_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_ioam_cache_ip6_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_disable;
} vl_api_ioam_cache_ip6_enable_disable_t;
#define VL_API_IOAM_CACHE_IP6_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ioam_cache_ip6_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ioam_cache_ip6_enable_disable_reply_t;
#define VL_API_IOAM_CACHE_IP6_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_IOAM_CACHE_IP6_ENABLE_DISABLE_CRC "ioam_cache_ip6_enable_disable_47705c03"
#define VL_API_IOAM_CACHE_IP6_ENABLE_DISABLE_REPLY_CRC "ioam_cache_ip6_enable_disable_reply_e8d4e804"

#endif
