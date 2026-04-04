#ifndef included_qos_api_types_h
#define included_qos_api_types_h
#define VL_API_QOS_API_VERSION_MAJOR 1
#define VL_API_QOS_API_VERSION_MINOR 1
#define VL_API_QOS_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    QOS_API_SOURCE_EXT = 0,
    QOS_API_SOURCE_VLAN = 1,
    QOS_API_SOURCE_MPLS = 2,
    QOS_API_SOURCE_IP = 3,
} vl_api_qos_source_t;
STATIC_ASSERT(sizeof(vl_api_qos_source_t) == sizeof(u8), "size of API enum qos_source is wrong");
typedef struct __attribute__ ((packed)) _vl_api_qos_store {
    vl_api_interface_index_t sw_if_index;
    vl_api_qos_source_t input_source;
    u8 value;
} vl_api_qos_store_t;
#define VL_API_QOS_STORE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_record {
    vl_api_interface_index_t sw_if_index;
    vl_api_qos_source_t input_source;
} vl_api_qos_record_t;
#define VL_API_QOS_RECORD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_row {
    u8 outputs[256];
} vl_api_qos_egress_map_row_t;
#define VL_API_QOS_EGRESS_MAP_ROW_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map {
    u32 id;
    vl_api_qos_egress_map_row_t rows[4];
} vl_api_qos_egress_map_t;
#define VL_API_QOS_EGRESS_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark {
    u32 sw_if_index;
    u32 map_id;
    vl_api_qos_source_t output_source;
} vl_api_qos_mark_t;
#define VL_API_QOS_MARK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_store_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    vl_api_qos_store_t store;
} vl_api_qos_store_enable_disable_t;
#define VL_API_QOS_STORE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_store_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_store_enable_disable_reply_t;
#define VL_API_QOS_STORE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_store_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_qos_store_dump_t;
#define VL_API_QOS_STORE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_store_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_qos_store_t store;
} vl_api_qos_store_details_t;
#define VL_API_QOS_STORE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_record_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    vl_api_qos_record_t record;
} vl_api_qos_record_enable_disable_t;
#define VL_API_QOS_RECORD_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_record_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_record_enable_disable_reply_t;
#define VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_record_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_qos_record_dump_t;
#define VL_API_QOS_RECORD_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_record_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_qos_record_t record;
} vl_api_qos_record_details_t;
#define VL_API_QOS_RECORD_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_qos_egress_map_t map;
} vl_api_qos_egress_map_update_t;
#define VL_API_QOS_EGRESS_MAP_UPDATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_egress_map_update_reply_t;
#define VL_API_QOS_EGRESS_MAP_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 id;
} vl_api_qos_egress_map_delete_t;
#define VL_API_QOS_EGRESS_MAP_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_egress_map_delete_reply_t;
#define VL_API_QOS_EGRESS_MAP_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_qos_egress_map_dump_t;
#define VL_API_QOS_EGRESS_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_egress_map_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_qos_egress_map_t map;
} vl_api_qos_egress_map_details_t;
#define VL_API_QOS_EGRESS_MAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
    vl_api_qos_mark_t mark;
} vl_api_qos_mark_enable_disable_t;
#define VL_API_QOS_MARK_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_mark_enable_disable_reply_t;
#define VL_API_QOS_MARK_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_qos_mark_dump_t;
#define VL_API_QOS_MARK_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_qos_mark_t mark;
} vl_api_qos_mark_details_t;
#define VL_API_QOS_MARK_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_qos_mark_details_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_qos_mark_details_reply_t;
#define VL_API_QOS_MARK_DETAILS_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_QOS_STORE_ENABLE_DISABLE_CRC "qos_store_enable_disable_f3abcc8b"
#define VL_API_QOS_STORE_ENABLE_DISABLE_REPLY_CRC "qos_store_enable_disable_reply_e8d4e804"
#define VL_API_QOS_STORE_DUMP_CRC "qos_store_dump_51077d14"
#define VL_API_QOS_STORE_DETAILS_CRC "qos_store_details_3ee0aad7"
#define VL_API_QOS_RECORD_ENABLE_DISABLE_CRC "qos_record_enable_disable_2f1a4a38"
#define VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY_CRC "qos_record_enable_disable_reply_e8d4e804"
#define VL_API_QOS_RECORD_DUMP_CRC "qos_record_dump_51077d14"
#define VL_API_QOS_RECORD_DETAILS_CRC "qos_record_details_a425d4d3"
#define VL_API_QOS_EGRESS_MAP_UPDATE_CRC "qos_egress_map_update_6d1c065f"
#define VL_API_QOS_EGRESS_MAP_UPDATE_REPLY_CRC "qos_egress_map_update_reply_e8d4e804"
#define VL_API_QOS_EGRESS_MAP_DELETE_CRC "qos_egress_map_delete_3a91bde5"
#define VL_API_QOS_EGRESS_MAP_DELETE_REPLY_CRC "qos_egress_map_delete_reply_e8d4e804"
#define VL_API_QOS_EGRESS_MAP_DUMP_CRC "qos_egress_map_dump_51077d14"
#define VL_API_QOS_EGRESS_MAP_DETAILS_CRC "qos_egress_map_details_46c5653c"
#define VL_API_QOS_MARK_ENABLE_DISABLE_CRC "qos_mark_enable_disable_1a010f74"
#define VL_API_QOS_MARK_ENABLE_DISABLE_REPLY_CRC "qos_mark_enable_disable_reply_e8d4e804"
#define VL_API_QOS_MARK_DUMP_CRC "qos_mark_dump_f9e6675e"
#define VL_API_QOS_MARK_DETAILS_CRC "qos_mark_details_89fe81a9"
#define VL_API_QOS_MARK_DETAILS_REPLY_CRC "qos_mark_details_reply_e8d4e804"

#endif
