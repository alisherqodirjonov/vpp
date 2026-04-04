#ifndef included_nat_types_api_types_h
#define included_nat_types_api_types_h
#define VL_API_NAT_TYPES_API_VERSION_MAJOR 0
#define VL_API_NAT_TYPES_API_VERSION_MINOR 0
#define VL_API_NAT_TYPES_API_VERSION_PATCH 1
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_nat_timeouts {
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_nat_timeouts_t;
#define VL_API_NAT_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef enum __attribute__((packed)) {
    NAT_LOG_NONE = 0,
    NAT_LOG_ERROR = 1,
    NAT_LOG_WARNING = 2,
    NAT_LOG_NOTICE = 3,
    NAT_LOG_INFO = 4,
    NAT_LOG_DEBUG = 5,
} vl_api_nat_log_level_t;
STATIC_ASSERT(sizeof(vl_api_nat_log_level_t) == sizeof(u8), "size of API enum nat_log_level is wrong");
typedef enum __attribute__((packed)) {
    NAT_IS_NONE = 0,
    NAT_IS_TWICE_NAT = 1,
    NAT_IS_SELF_TWICE_NAT = 2,
    NAT_IS_OUT2IN_ONLY = 4,
    NAT_IS_ADDR_ONLY = 8,
    NAT_IS_OUTSIDE = 16,
    NAT_IS_INSIDE = 32,
    NAT_IS_STATIC = 64,
    NAT_IS_EXT_HOST_VALID = 128,
} vl_api_nat_config_flags_t;
STATIC_ASSERT(sizeof(vl_api_nat_config_flags_t) == sizeof(u8), "size of API enum nat_config_flags is wrong");

#endif
