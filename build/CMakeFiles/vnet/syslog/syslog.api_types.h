#ifndef included_syslog_api_types_h
#define included_syslog_api_types_h
#define VL_API_SYSLOG_API_VERSION_MAJOR 1
#define VL_API_SYSLOG_API_VERSION_MINOR 0
#define VL_API_SYSLOG_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    SYSLOG_API_SEVERITY_EMERG = 0,
    SYSLOG_API_SEVERITY_ALERT = 1,
    SYSLOG_API_SEVERITY_CRIT = 2,
    SYSLOG_API_SEVERITY_ERR = 3,
    SYSLOG_API_SEVERITY_WARN = 4,
    SYSLOG_API_SEVERITY_NOTICE = 5,
    SYSLOG_API_SEVERITY_INFO = 6,
    SYSLOG_API_SEVERITY_DBG = 7,
} vl_api_syslog_severity_t;
typedef struct __attribute__ ((packed)) _vl_api_syslog_set_sender {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t src_address;
    vl_api_ip4_address_t collector_address;
    u16 collector_port;
    u32 vrf_id;
    u32 max_msg_size;
} vl_api_syslog_set_sender_t;
#define VL_API_SYSLOG_SET_SENDER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_set_sender_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_syslog_set_sender_reply_t;
#define VL_API_SYSLOG_SET_SENDER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_get_sender {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_syslog_get_sender_t;
#define VL_API_SYSLOG_GET_SENDER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_get_sender_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_ip4_address_t src_address;
    vl_api_ip4_address_t collector_address;
    u16 collector_port;
    u32 vrf_id;
    u32 max_msg_size;
} vl_api_syslog_get_sender_reply_t;
#define VL_API_SYSLOG_GET_SENDER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_set_filter {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_syslog_severity_t severity;
} vl_api_syslog_set_filter_t;
#define VL_API_SYSLOG_SET_FILTER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_set_filter_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_syslog_set_filter_reply_t;
#define VL_API_SYSLOG_SET_FILTER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_get_filter {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_syslog_get_filter_t;
#define VL_API_SYSLOG_GET_FILTER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_syslog_get_filter_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_syslog_severity_t severity;
} vl_api_syslog_get_filter_reply_t;
#define VL_API_SYSLOG_GET_FILTER_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_SYSLOG_SET_SENDER_CRC "syslog_set_sender_b8011d0b"
#define VL_API_SYSLOG_SET_SENDER_REPLY_CRC "syslog_set_sender_reply_e8d4e804"
#define VL_API_SYSLOG_GET_SENDER_CRC "syslog_get_sender_51077d14"
#define VL_API_SYSLOG_GET_SENDER_REPLY_CRC "syslog_get_sender_reply_424cfa4e"
#define VL_API_SYSLOG_SET_FILTER_CRC "syslog_set_filter_571348c3"
#define VL_API_SYSLOG_SET_FILTER_REPLY_CRC "syslog_set_filter_reply_e8d4e804"
#define VL_API_SYSLOG_GET_FILTER_CRC "syslog_get_filter_51077d14"
#define VL_API_SYSLOG_GET_FILTER_REPLY_CRC "syslog_get_filter_reply_eb1833f8"

#endif
