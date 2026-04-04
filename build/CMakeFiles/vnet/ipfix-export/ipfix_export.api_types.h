#ifndef included_ipfix_export_api_types_h
#define included_ipfix_export_api_types_h
#define VL_API_IPFIX_EXPORT_API_VERSION_MAJOR 2
#define VL_API_IPFIX_EXPORT_API_VERSION_MINOR 0
#define VL_API_IPFIX_EXPORT_API_VERSION_PATCH 3
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_set_ipfix_exporter {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t collector_address;
    u16 collector_port;
    vl_api_address_t src_address;
    u32 vrf_id;
    u32 path_mtu;
    u32 template_interval;
    bool udp_checksum;
} vl_api_set_ipfix_exporter_t;
#define VL_API_SET_IPFIX_EXPORTER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_set_ipfix_exporter_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_set_ipfix_exporter_reply_t;
#define VL_API_SET_IPFIX_EXPORTER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_exporter_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipfix_exporter_dump_t;
#define VL_API_IPFIX_EXPORTER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_exporter_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t collector_address;
    u16 collector_port;
    vl_api_address_t src_address;
    u32 vrf_id;
    u32 path_mtu;
    u32 template_interval;
    bool udp_checksum;
} vl_api_ipfix_exporter_details_t;
#define VL_API_IPFIX_EXPORTER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_exporter_create_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_create;
    vl_api_address_t collector_address;
    u16 collector_port;
    vl_api_address_t src_address;
    u32 vrf_id;
    u32 path_mtu;
    u32 template_interval;
    bool udp_checksum;
} vl_api_ipfix_exporter_create_delete_t;
#define VL_API_IPFIX_EXPORTER_CREATE_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_exporter_create_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stat_index;
} vl_api_ipfix_exporter_create_delete_reply_t;
#define VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_all_exporter_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_ipfix_all_exporter_get_t;
#define VL_API_IPFIX_ALL_EXPORTER_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_all_exporter_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_ipfix_all_exporter_get_reply_t;
#define VL_API_IPFIX_ALL_EXPORTER_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_all_exporter_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t collector_address;
    u16 collector_port;
    vl_api_address_t src_address;
    u32 vrf_id;
    u32 path_mtu;
    u32 template_interval;
    bool udp_checksum;
} vl_api_ipfix_all_exporter_details_t;
#define VL_API_IPFIX_ALL_EXPORTER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_set_ipfix_classify_stream {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 domain_id;
    u16 src_port;
} vl_api_set_ipfix_classify_stream_t;
#define VL_API_SET_IPFIX_CLASSIFY_STREAM_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_set_ipfix_classify_stream_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_set_ipfix_classify_stream_reply_t;
#define VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_stream_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipfix_classify_stream_dump_t;
#define VL_API_IPFIX_CLASSIFY_STREAM_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_stream_details {
    u16 _vl_msg_id;
    u32 context;
    u32 domain_id;
    u16 src_port;
} vl_api_ipfix_classify_stream_details_t;
#define VL_API_IPFIX_CLASSIFY_STREAM_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_table_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_id;
    vl_api_address_family_t ip_version;
    vl_api_ip_proto_t transport_protocol;
    bool is_add;
} vl_api_ipfix_classify_table_add_del_t;
#define VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_table_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipfix_classify_table_add_del_reply_t;
#define VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipfix_classify_table_dump_t;
#define VL_API_IPFIX_CLASSIFY_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_classify_table_details {
    u16 _vl_msg_id;
    u32 context;
    u32 table_id;
    vl_api_address_family_t ip_version;
    vl_api_ip_proto_t transport_protocol;
} vl_api_ipfix_classify_table_details_t;
#define VL_API_IPFIX_CLASSIFY_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_flush {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_ipfix_flush_t;
#define VL_API_IPFIX_FLUSH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipfix_flush_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipfix_flush_reply_t;
#define VL_API_IPFIX_FLUSH_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_SET_IPFIX_EXPORTER_CRC "set_ipfix_exporter_5530c8a0"
#define VL_API_SET_IPFIX_EXPORTER_REPLY_CRC "set_ipfix_exporter_reply_e8d4e804"
#define VL_API_IPFIX_EXPORTER_DUMP_CRC "ipfix_exporter_dump_51077d14"
#define VL_API_IPFIX_EXPORTER_DETAILS_CRC "ipfix_exporter_details_0dedbfe4"
#define VL_API_IPFIX_EXPORTER_CREATE_DELETE_CRC "ipfix_exporter_create_delete_0753a768"
#define VL_API_IPFIX_EXPORTER_CREATE_DELETE_REPLY_CRC "ipfix_exporter_create_delete_reply_9ffac24b"
#define VL_API_IPFIX_ALL_EXPORTER_GET_CRC "ipfix_all_exporter_get_f75ba505"
#define VL_API_IPFIX_ALL_EXPORTER_GET_REPLY_CRC "ipfix_all_exporter_get_reply_53b48f5d"
#define VL_API_IPFIX_ALL_EXPORTER_DETAILS_CRC "ipfix_all_exporter_details_0dedbfe4"
#define VL_API_SET_IPFIX_CLASSIFY_STREAM_CRC "set_ipfix_classify_stream_c9cbe053"
#define VL_API_SET_IPFIX_CLASSIFY_STREAM_REPLY_CRC "set_ipfix_classify_stream_reply_e8d4e804"
#define VL_API_IPFIX_CLASSIFY_STREAM_DUMP_CRC "ipfix_classify_stream_dump_51077d14"
#define VL_API_IPFIX_CLASSIFY_STREAM_DETAILS_CRC "ipfix_classify_stream_details_2903539d"
#define VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_CRC "ipfix_classify_table_add_del_3e449bb9"
#define VL_API_IPFIX_CLASSIFY_TABLE_ADD_DEL_REPLY_CRC "ipfix_classify_table_add_del_reply_e8d4e804"
#define VL_API_IPFIX_CLASSIFY_TABLE_DUMP_CRC "ipfix_classify_table_dump_51077d14"
#define VL_API_IPFIX_CLASSIFY_TABLE_DETAILS_CRC "ipfix_classify_table_details_1af8c28c"
#define VL_API_IPFIX_FLUSH_CRC "ipfix_flush_51077d14"
#define VL_API_IPFIX_FLUSH_REPLY_CRC "ipfix_flush_reply_e8d4e804"

#endif
