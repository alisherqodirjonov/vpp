#ifndef included_sflow_api_types_h
#define included_sflow_api_types_h
#define VL_API_SFLOW_API_VERSION_MAJOR 0
#define VL_API_SFLOW_API_VERSION_MINOR 1
#define VL_API_SFLOW_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_sflow_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_disable;
    vl_api_interface_index_t hw_if_index;
} vl_api_sflow_enable_disable_t;
#define VL_API_SFLOW_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_enable_disable_reply_t;
#define VL_API_SFLOW_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_sampling_rate_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sflow_sampling_rate_get_t;
#define VL_API_SFLOW_SAMPLING_RATE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_sampling_rate_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 sampling_N;
} vl_api_sflow_sampling_rate_get_reply_t;
#define VL_API_SFLOW_SAMPLING_RATE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_sampling_rate_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sampling_N;
} vl_api_sflow_sampling_rate_set_t;
#define VL_API_SFLOW_SAMPLING_RATE_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_sampling_rate_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_sampling_rate_set_reply_t;
#define VL_API_SFLOW_SAMPLING_RATE_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_polling_interval_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 polling_S;
} vl_api_sflow_polling_interval_set_t;
#define VL_API_SFLOW_POLLING_INTERVAL_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_polling_interval_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_polling_interval_set_reply_t;
#define VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_polling_interval_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sflow_polling_interval_get_t;
#define VL_API_SFLOW_POLLING_INTERVAL_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_polling_interval_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 polling_S;
} vl_api_sflow_polling_interval_get_reply_t;
#define VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_header_bytes_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 header_B;
} vl_api_sflow_header_bytes_set_t;
#define VL_API_SFLOW_HEADER_BYTES_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_header_bytes_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_header_bytes_set_reply_t;
#define VL_API_SFLOW_HEADER_BYTES_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_header_bytes_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sflow_header_bytes_get_t;
#define VL_API_SFLOW_HEADER_BYTES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_header_bytes_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 header_B;
} vl_api_sflow_header_bytes_get_reply_t;
#define VL_API_SFLOW_HEADER_BYTES_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_direction_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sampling_D;
} vl_api_sflow_direction_set_t;
#define VL_API_SFLOW_DIRECTION_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_direction_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_direction_set_reply_t;
#define VL_API_SFLOW_DIRECTION_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_direction_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sflow_direction_get_t;
#define VL_API_SFLOW_DIRECTION_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_direction_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 sampling_D;
} vl_api_sflow_direction_get_reply_t;
#define VL_API_SFLOW_DIRECTION_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_drop_monitoring_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 drop_M;
} vl_api_sflow_drop_monitoring_set_t;
#define VL_API_SFLOW_DROP_MONITORING_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_drop_monitoring_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sflow_drop_monitoring_set_reply_t;
#define VL_API_SFLOW_DROP_MONITORING_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_drop_monitoring_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sflow_drop_monitoring_get_t;
#define VL_API_SFLOW_DROP_MONITORING_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_drop_monitoring_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 drop_M;
} vl_api_sflow_drop_monitoring_get_reply_t;
#define VL_API_SFLOW_DROP_MONITORING_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t hw_if_index;
} vl_api_sflow_interface_dump_t;
#define VL_API_SFLOW_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sflow_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t hw_if_index;
} vl_api_sflow_interface_details_t;
#define VL_API_SFLOW_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SFLOW_ENABLE_DISABLE_CRC "sflow_enable_disable_8499814f"
#define VL_API_SFLOW_ENABLE_DISABLE_REPLY_CRC "sflow_enable_disable_reply_e8d4e804"
#define VL_API_SFLOW_SAMPLING_RATE_GET_CRC "sflow_sampling_rate_get_51077d14"
#define VL_API_SFLOW_SAMPLING_RATE_GET_REPLY_CRC "sflow_sampling_rate_get_reply_9c8c8236"
#define VL_API_SFLOW_SAMPLING_RATE_SET_CRC "sflow_sampling_rate_set_94778f50"
#define VL_API_SFLOW_SAMPLING_RATE_SET_REPLY_CRC "sflow_sampling_rate_set_reply_e8d4e804"
#define VL_API_SFLOW_POLLING_INTERVAL_SET_CRC "sflow_polling_interval_set_7f19cb51"
#define VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY_CRC "sflow_polling_interval_set_reply_e8d4e804"
#define VL_API_SFLOW_POLLING_INTERVAL_GET_CRC "sflow_polling_interval_get_51077d14"
#define VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY_CRC "sflow_polling_interval_get_reply_e929801c"
#define VL_API_SFLOW_HEADER_BYTES_SET_CRC "sflow_header_bytes_set_5baf56f3"
#define VL_API_SFLOW_HEADER_BYTES_SET_REPLY_CRC "sflow_header_bytes_set_reply_e8d4e804"
#define VL_API_SFLOW_HEADER_BYTES_GET_CRC "sflow_header_bytes_get_51077d14"
#define VL_API_SFLOW_HEADER_BYTES_GET_REPLY_CRC "sflow_header_bytes_get_reply_624c95b9"
#define VL_API_SFLOW_DIRECTION_SET_CRC "sflow_direction_set_fbca6f34"
#define VL_API_SFLOW_DIRECTION_SET_REPLY_CRC "sflow_direction_set_reply_e8d4e804"
#define VL_API_SFLOW_DIRECTION_GET_CRC "sflow_direction_get_51077d14"
#define VL_API_SFLOW_DIRECTION_GET_REPLY_CRC "sflow_direction_get_reply_f3316252"
#define VL_API_SFLOW_DROP_MONITORING_SET_CRC "sflow_drop_monitoring_set_100b1e04"
#define VL_API_SFLOW_DROP_MONITORING_SET_REPLY_CRC "sflow_drop_monitoring_set_reply_e8d4e804"
#define VL_API_SFLOW_DROP_MONITORING_GET_CRC "sflow_drop_monitoring_get_51077d14"
#define VL_API_SFLOW_DROP_MONITORING_GET_REPLY_CRC "sflow_drop_monitoring_get_reply_b56ae30e"
#define VL_API_SFLOW_INTERFACE_DUMP_CRC "sflow_interface_dump_451a727d"
#define VL_API_SFLOW_INTERFACE_DETAILS_CRC "sflow_interface_details_b7b9143f"

#endif
