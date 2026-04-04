#ifndef included_vpe_api_types_h
#define included_vpe_api_types_h
#define VL_API_VPE_API_VERSION_MAJOR 1
#define VL_API_VPE_API_VERSION_MINOR 7
#define VL_API_VPE_API_VERSION_PATCH 0
/* Imported API files */
#include <vpp/api/vpe_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_show_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_version_t;
#define VL_API_SHOW_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_version_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 program[32];
    u8 version[32];
    u8 build_date[32];
    u8 build_directory[256];
} vl_api_show_version_reply_t;
#define VL_API_SHOW_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_vpe_system_time {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_vpe_system_time_t;
#define VL_API_SHOW_VPE_SYSTEM_TIME_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_vpe_system_time_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_timestamp_t vpe_system_time;
} vl_api_show_vpe_system_time_reply_t;
#define VL_API_SHOW_VPE_SYSTEM_TIME_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_log_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_timestamp_t start_timestamp;
} vl_api_log_dump_t;
#define VL_API_LOG_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_log_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_timestamp_t timestamp;
    vl_api_log_level_t level;
    u8 msg_class[32];
    u8 message[256];
} vl_api_log_details_t;
#define VL_API_LOG_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SHOW_VERSION_CRC "show_version_51077d14"
#define VL_API_SHOW_VERSION_REPLY_CRC "show_version_reply_c919bde1"
#define VL_API_SHOW_VPE_SYSTEM_TIME_CRC "show_vpe_system_time_51077d14"
#define VL_API_SHOW_VPE_SYSTEM_TIME_REPLY_CRC "show_vpe_system_time_reply_7ffd8193"
#define VL_API_LOG_DUMP_CRC "log_dump_6ab31753"
#define VL_API_LOG_DETAILS_CRC "log_details_03d61cc0"

#endif
