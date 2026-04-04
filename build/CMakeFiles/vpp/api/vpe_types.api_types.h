#ifndef included_vpe_types_api_types_h
#define included_vpe_types_api_types_h
#define VL_API_VPE_TYPES_API_VERSION_MAJOR 1
#define VL_API_VPE_TYPES_API_VERSION_MINOR 0
#define VL_API_VPE_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_version {
    u32 major;
    u32 minor;
    u32 patch;
    u8 pre_release[17];
    u8 build_metadata[17];
} vl_api_version_t;
#define VL_API_VERSION_IS_CONSTANT_SIZE (1)

typedef f64 vl_api_timestamp_t;
typedef f64 vl_api_timedelta_t;
typedef enum {
    VPE_API_LOG_LEVEL_EMERG = 0,
    VPE_API_LOG_LEVEL_ALERT = 1,
    VPE_API_LOG_LEVEL_CRIT = 2,
    VPE_API_LOG_LEVEL_ERR = 3,
    VPE_API_LOG_LEVEL_WARNING = 4,
    VPE_API_LOG_LEVEL_NOTICE = 5,
    VPE_API_LOG_LEVEL_INFO = 6,
    VPE_API_LOG_LEVEL_DEBUG = 7,
    VPE_API_LOG_LEVEL_DISABLED = 8,
} vl_api_log_level_t;

#endif
