#ifndef included_mactime_api_types_h
#define included_mactime_api_types_h
#define VL_API_MACTIME_API_VERSION_MAJOR 2
#define VL_API_MACTIME_API_VERSION_MINOR 0
#define VL_API_MACTIME_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_time_range {
    f64 start;
    f64 end;
} vl_api_time_range_t;
#define VL_API_TIME_RANGE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_time_range {
    f64 start;
    f64 end;
} vl_api_mactime_time_range_t;
#define VL_API_MACTIME_TIME_RANGE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_disable;
    vl_api_interface_index_t sw_if_index;
} vl_api_mactime_enable_disable_t;
#define VL_API_MACTIME_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mactime_enable_disable_reply_t;
#define VL_API_MACTIME_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_add_del_range {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool drop;
    bool allow;
    u8 allow_quota;
    bool no_udp_10001;
    u64 data_quota;
    vl_api_mac_address_t mac_address;
    u8 device_name[64];
    u32 count;
    vl_api_time_range_t ranges[0];
} vl_api_mactime_add_del_range_t;
#define VL_API_MACTIME_ADD_DEL_RANGE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mactime_add_del_range_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mactime_add_del_range_reply_t;
#define VL_API_MACTIME_ADD_DEL_RANGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 my_table_epoch;
} vl_api_mactime_dump_t;
#define VL_API_MACTIME_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mactime_details {
    u16 _vl_msg_id;
    u32 context;
    u32 pool_index;
    vl_api_mac_address_t mac_address;
    u64 data_quota;
    u64 data_used_in_range;
    u32 flags;
    u8 device_name[64];
    u32 nranges;
    vl_api_mactime_time_range_t ranges[0];
} vl_api_mactime_details_t;
#define VL_API_MACTIME_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mactime_dump_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_epoch;
} vl_api_mactime_dump_reply_t;
#define VL_API_MACTIME_DUMP_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_MACTIME_ENABLE_DISABLE_CRC "mactime_enable_disable_3865946c"
#define VL_API_MACTIME_ENABLE_DISABLE_REPLY_CRC "mactime_enable_disable_reply_e8d4e804"
#define VL_API_MACTIME_ADD_DEL_RANGE_CRC "mactime_add_del_range_cb56e877"
#define VL_API_MACTIME_ADD_DEL_RANGE_REPLY_CRC "mactime_add_del_range_reply_e8d4e804"
#define VL_API_MACTIME_DUMP_CRC "mactime_dump_8f454e23"
#define VL_API_MACTIME_DETAILS_CRC "mactime_details_da25b13a"
#define VL_API_MACTIME_DUMP_REPLY_CRC "mactime_dump_reply_49bcc753"

#endif
