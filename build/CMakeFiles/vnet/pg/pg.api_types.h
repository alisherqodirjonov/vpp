#ifndef included_pg_api_types_h
#define included_pg_api_types_h
#define VL_API_PG_API_VERSION_MAJOR 2
#define VL_API_PG_API_VERSION_MINOR 1
#define VL_API_PG_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    PG_API_MODE_ETHERNET = 0,
    PG_API_MODE_IP4 = 1,
    PG_API_MODE_IP6 = 2,
} vl_api_pg_interface_mode_t;
STATIC_ASSERT(sizeof(vl_api_pg_interface_mode_t) == sizeof(u8), "size of API enum pg_interface_mode is wrong");
typedef enum {
    PG_API_FLAG_NONE = 0,
    PG_API_FLAG_CSUM_OFFLOAD = 1,
    PG_API_FLAG_GSO = 2,
    PG_API_FLAG_GRO_COALESCE = 4,
} vl_api_pg_interface_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t interface_id;
    bool gso_enabled;
    u32 gso_size;
} vl_api_pg_create_interface_t;
#define VL_API_PG_CREATE_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t interface_id;
    bool gso_enabled;
    u32 gso_size;
    vl_api_pg_interface_mode_t mode;
} vl_api_pg_create_interface_v2_t;
#define VL_API_PG_CREATE_INTERFACE_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface_v3 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t interface_id;
    vl_api_pg_interface_flags_t pg_flags;
    u32 gso_size;
    vl_api_pg_interface_mode_t mode;
} vl_api_pg_create_interface_v3_t;
#define VL_API_PG_CREATE_INTERFACE_V3_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_pg_create_interface_reply_t;
#define VL_API_PG_CREATE_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_pg_create_interface_v2_reply_t;
#define VL_API_PG_CREATE_INTERFACE_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_create_interface_v3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_pg_create_interface_v3_reply_t;
#define VL_API_PG_CREATE_INTERFACE_V3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_delete_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_pg_delete_interface_t;
#define VL_API_PG_DELETE_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_delete_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pg_delete_interface_reply_t;
#define VL_API_PG_DELETE_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_interface_enable_disable_coalesce {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool coalesce_enabled;
} vl_api_pg_interface_enable_disable_coalesce_t;
#define VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_interface_enable_disable_coalesce_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pg_interface_enable_disable_coalesce_reply_t;
#define VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_capture {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t interface_id;
    bool is_enabled;
    u32 count;
    vl_api_string_t pcap_file_name;
} vl_api_pg_capture_t;
#define VL_API_PG_CAPTURE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_pg_capture_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pg_capture_reply_t;
#define VL_API_PG_CAPTURE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pg_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enabled;
    vl_api_string_t stream_name;
} vl_api_pg_enable_disable_t;
#define VL_API_PG_ENABLE_DISABLE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_pg_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pg_enable_disable_reply_t;
#define VL_API_PG_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_PG_CREATE_INTERFACE_CRC "pg_create_interface_b7c893d7"
#define VL_API_PG_CREATE_INTERFACE_V2_CRC "pg_create_interface_v2_8657466a"
#define VL_API_PG_CREATE_INTERFACE_V3_CRC "pg_create_interface_v3_b2aac653"
#define VL_API_PG_CREATE_INTERFACE_REPLY_CRC "pg_create_interface_reply_5383d31f"
#define VL_API_PG_CREATE_INTERFACE_V2_REPLY_CRC "pg_create_interface_v2_reply_5383d31f"
#define VL_API_PG_CREATE_INTERFACE_V3_REPLY_CRC "pg_create_interface_v3_reply_5383d31f"
#define VL_API_PG_DELETE_INTERFACE_CRC "pg_delete_interface_f9e6675e"
#define VL_API_PG_DELETE_INTERFACE_REPLY_CRC "pg_delete_interface_reply_e8d4e804"
#define VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_CRC "pg_interface_enable_disable_coalesce_a2ef99e7"
#define VL_API_PG_INTERFACE_ENABLE_DISABLE_COALESCE_REPLY_CRC "pg_interface_enable_disable_coalesce_reply_e8d4e804"
#define VL_API_PG_CAPTURE_CRC "pg_capture_3712fb6c"
#define VL_API_PG_CAPTURE_REPLY_CRC "pg_capture_reply_e8d4e804"
#define VL_API_PG_ENABLE_DISABLE_CRC "pg_enable_disable_01f94f3a"
#define VL_API_PG_ENABLE_DISABLE_REPLY_CRC "pg_enable_disable_reply_e8d4e804"

#endif
